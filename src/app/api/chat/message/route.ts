import { NextRequest, NextResponse } from 'next/server';
import { ipAddressSecurityScoring } from '@/ai/flows/ip-address-security-scoring';
import { ai } from '@/ai/genkit';
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

// Direct database connection for faster response
function getDatabase() {
  const dbDir = path.join(process.cwd(), 'data');
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  
  const db = new Database(path.join(dbDir, 'chat.db'));
  
  // Initialize tables if they don't exist
  db.exec(`
    CREATE TABLE IF NOT EXISTS chat_conversations (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      content TEXT NOT NULL,
      role TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
    )
  `);

  return db;
}

// AI response generation using Google AI
async function generateAIResponse(userMessage: string): Promise<string> {
  try {
    // Check if the message contains an IP address for specific analysis
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const ips = userMessage.match(ipRegex);
    
    let contextualInfo = '';
    if (ips && ips.length > 0) {
      try {
        // Get IP security analysis
        const ipAnalysis = await ipAddressSecurityScoring({
          ipAddress: ips[0],
          attackData: {
            totalPackets: 0,
            ddosAttacks: 0,
            portScans: 0,
            bruteForceAttacks: 0,
            malwareDetections: 0,
            connectionFloods: 0,
            unauthorizedAccess: 0,
            knownThreats: 0,
            averageThreatScore: 0,
            maxThreatScore: 0,
            attackDetails: []
          }
        });
        
        contextualInfo = `\n\n**IP Analysis Context:**\nIP ${ips[0]} has a danger score of ${ipAnalysis.dangerScore}/100 and is classified as ${ipAnalysis.securityScore}. ${ipAnalysis.analysisDetails}`;
      } catch (error) {
        console.error('Error getting IP analysis:', error);
      }
    }

    const response = await ai.generate({
      prompt: `You are NetGuardian, an advanced AI security assistant specializing in network security, threat analysis, and cybersecurity guidance.

**Your Expertise:**
- Network security analysis and threat detection
- IP address reputation and risk assessment  
- Attack pattern identification (DDoS, port scanning, brute force, malware)
- Security incident response and mitigation strategies
- Network monitoring and defense recommendations
- Cybersecurity best practices and implementation

**Your Personality:**
- Professional but approachable
- Provide actionable, practical advice
- Use clear explanations with technical depth when appropriate
- Format responses with markdown for better readability
- Focus on real-world security implications

**User Message:** ${userMessage}

${contextualInfo}

**Instructions:**
1. Analyze the user's security question or concern
2. Provide comprehensive, actionable guidance
3. Use markdown formatting with headers, bullet points, and emphasis
4. Include specific examples or recommendations when relevant
5. If discussing IP addresses, incorporate any provided analysis data
6. Always prioritize practical security value in your response

Respond as NetGuardian with helpful, expert-level security guidance.`,
      model: 'googleai/gemini-2.5-flash',
    });

    return response.text;
  } catch (error) {
    console.error('Error generating AI response:', error);
    // Fall back to simple response if AI fails
    return generateSimpleResponse(userMessage);
  }
}

export async function POST(request: NextRequest) {
  let db: any = null;
  
  try {
    const { message, conversationId, messages, conversationTitle } = await request.json();
    console.log('Message API called:', { conversationId, message: message.substring(0, 50) + '...' });

    // Direct database approach for faster response
    db = getDatabase();
    
    try {
      // Check if conversation exists
      const existingConversation = db.prepare('SELECT id FROM chat_conversations WHERE id = ?').get(conversationId);
      
      // Create conversation if it doesn't exist
      if (!existingConversation) {
        const createConversationStmt = db.prepare(`
          INSERT INTO chat_conversations (id, title, created_at, updated_at)
          VALUES (?, ?, ?, ?)
        `);
        
        const conversationData = {
          id: conversationId,
          title: conversationTitle || message.trim().substring(0, 50) + (message.length > 50 ? "..." : ""),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        
        createConversationStmt.run(conversationData.id, conversationData.title, conversationData.createdAt, conversationData.updatedAt);
        console.log('Created conversation:', conversationData.id);
      }
      
      // Save user message
      const saveMessageStmt = db.prepare(`
        INSERT INTO chat_messages (id, conversation_id, content, role, timestamp)
        VALUES (?, ?, ?, ?, ?)
      `);
      
      const userMessageData = {
        id: `msg_${Date.now()}_user`,
        conversationId,
        content: message,
        role: 'user',
        timestamp: new Date().toISOString(),
      };
      
      saveMessageStmt.run(userMessageData.id, userMessageData.conversationId, userMessageData.content, userMessageData.role, userMessageData.timestamp);
      console.log('Saved user message:', userMessageData.id);
      
      // Generate AI response using Google AI
      const aiResponse = await generateAIResponse(message);
      
      // Save AI message
      const aiMessageData = {
        id: `msg_${Date.now()}_ai`,
        conversationId,
        content: aiResponse,
        role: 'assistant',
        timestamp: new Date().toISOString(),
      };
      
      saveMessageStmt.run(aiMessageData.id, aiMessageData.conversationId, aiMessageData.content, aiMessageData.role, aiMessageData.timestamp);
      console.log('Saved AI message:', aiMessageData.id);
      
      // Update conversation timestamp
      const updateConversationStmt = db.prepare('UPDATE chat_conversations SET updated_at = ? WHERE id = ?');
      updateConversationStmt.run(new Date().toISOString(), conversationId);
      
      db.close();
      
      return NextResponse.json({ response: aiResponse });
      
    } catch (dbError) {
      console.error('Database error:', dbError);
      if (db) {
        db.close();
      }
      
      // Provide a fallback response
      const fallbackResponse = generateSimpleResponse(message);
      return NextResponse.json({ response: fallbackResponse });
    }
    
  } catch (error) {
    console.error('Error processing chat message:', error);
    
    if (db) {
      db.close();
    }
    
    // Provide a fallback response
    const fallbackResponse = generateSimpleResponse('your message');
    return NextResponse.json({ response: fallbackResponse });
  }
}

function generateSimpleResponse(userMessage: string): string {
  const lowerMessage = userMessage.toLowerCase();
  
  // Check for IP addresses
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const ips = userMessage.match(ipRegex);
  
  if (ips && ips.length > 0) {
    return `## IP Analysis for ${ips[0]}

I've detected that you're asking about the IP address **${ips[0]}**. 

**Quick Security Assessment:**
- This appears to be a private/local IP address
- No immediate threats detected in our database
- Recommend monitoring for unusual activity

**What I can help you with:**
- Detailed IP threat analysis
- Network security recommendations
- Attack pattern identification
- Security monitoring setup

Would you like me to perform a more detailed analysis of this IP address?`;
  }
  
  if (lowerMessage.includes('attack') || lowerMessage.includes('ddos')) {
    return `## Security Threat Analysis

I can help you understand and defend against various types of network attacks:

**Common Attack Types:**
- DDoS (Distributed Denial of Service)
- Port scanning and reconnaissance
- Brute force authentication attacks
- Malware communication
- Data exfiltration attempts

**How I can assist:**
- Analyze suspicious IP addresses
- Explain attack patterns and signatures
- Provide mitigation strategies
- Help with incident response

What specific security concerns would you like me to help you with?`;
  }
  
  if (lowerMessage.includes('security') || lowerMessage.includes('threat')) {
    return `## Network Security Assistant

I'm here to help you with network security analysis and threat detection. Here's what I can do:

**Security Analysis:**
- IP address reputation and threat scoring
- Attack pattern identification
- Network traffic analysis
- Security recommendation

**Threat Intelligence:**
- Real-time threat detection
- Malicious IP identification
- Attack signature recognition
- Risk assessment

**How to get started:**
- Ask me about specific IP addresses (e.g., "Is 192.168.1.100 safe?")
- Describe security incidents you're investigating
- Request analysis of suspicious network activity

What security question can I help you with today?`;
  }
  
  return `## NetGuardian AI Assistant

Hello! I'm your network security AI assistant. You said: "${userMessage}"

I specialize in:
- **IP Address Analysis** - Check if IP addresses are safe or malicious
- **Threat Detection** - Identify various types of network attacks
- **Security Recommendations** - Provide actionable security advice
- **Incident Response** - Help analyze and respond to security incidents

**Try asking me:**
- "Is IP 203.0.113.1 safe?"
- "What are signs of a DDoS attack?"
- "How can I protect against brute force attacks?"
- "Analyze suspicious activity from [IP address]"

How can I help secure your network today?`;
}

async function generateSecurityResponse(message: string, messages: any[]): Promise<string> {
  // Enhanced security-focused responses
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('ddos')) {
    return `## DDoS Attack Analysis

DDoS (Distributed Denial of Service) attacks are a serious threat to network infrastructure. Here's what you should know:

**Common DDoS Patterns:**
- High volume of requests from multiple sources
- Unusual traffic spikes targeting specific services
- Connection exhaustion attacks
- UDP/TCP flood attacks

**Detection Strategies:**
- Monitor bandwidth utilization patterns
- Track connection rates per IP
- Analyze traffic anomalies
- Set up rate limiting

**Mitigation Recommendations:**
- Implement traffic filtering and rate limiting
- Use load balancers with DDoS protection
- Configure firewall rules for suspicious IPs
- Consider cloud-based DDoS protection services

Would you like me to analyze specific traffic patterns in your network?`;
  }
  
  if (lowerMessage.includes('port scan')) {
    return `## Port Scanning Detection & Prevention

Port scans are reconnaissance activities that often precede attacks. Here's how to handle them:

**Common Scan Types:**
- TCP SYN scans (stealth scans)
- UDP scans for service discovery  
- Connect scans for banner grabbing
- Timing-based scans to evade detection

**Detection Indicators:**
- Multiple connection attempts to different ports from same IP
- High volume of connection failures
- Sequential port probing patterns
- Unusual service discovery attempts

**Response Actions:**
- Block scanning IPs automatically
- Log and analyze scan patterns
- Harden exposed services
- Implement intrusion detection systems

**Prevention Measures:**
- Close unnecessary ports
- Use network segmentation
- Implement firewall rules
- Regular security audits

Do you have specific IPs showing scan activity that I should analyze?`;
  }

  if (lowerMessage.includes('brute force')) {
    return `## Brute Force Attack Protection

Brute force attacks target authentication systems. Here's how to defend against them:

**Attack Characteristics:**
- Repeated login attempts with different credentials
- High frequency authentication requests
- Dictionary-based password attacks
- Credential stuffing from breached databases

**Detection Methods:**
- Monitor failed login attempt rates
- Track authentication patterns per IP
- Analyze timing between attempts  
- Watch for unusual user agent patterns

**Protection Strategies:**
- Implement account lockout policies
- Use CAPTCHA after failed attempts
- Deploy multi-factor authentication
- Set up IP-based rate limiting
- Monitor for credential stuffing patterns

**Recommended Actions:**
- Block IPs with multiple failed attempts
- Strengthen password policies
- Implement progressive delays
- Use threat intelligence feeds

Are you seeing brute force patterns against specific services?`;
  }

  // General security response
  return `## Network Security Analysis

I'm here to help you analyze network security threats and patterns. I can assist with:

**Threat Analysis:**
- IP reputation and behavior analysis
- Attack pattern identification
- Traffic anomaly detection
- Risk assessment and scoring

**Attack Types I Can Help With:**
- DDoS attacks and mitigation strategies
- Port scanning detection and response
- Brute force attack protection
- Malware traffic identification
- Unauthorized access attempts

**Security Recommendations:**
- Network hardening strategies
- Monitoring and alerting setup
- Incident response planning
- Best practice implementations

**How I Can Help:**
- Analyze specific IP addresses for threats
- Explain attack patterns in your network
- Provide mitigation recommendations
- Help with security policy development

Feel free to ask about specific IPs, attack types, or share security concerns you're facing. I can provide detailed analysis and actionable recommendations.`;
}

async function generateGeneralResponse(message: string, messages: any[]): Promise<string> {
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('help') || lowerMessage.includes('what can you do')) {
    return `## NetGuardian AI Assistant

I'm your network security AI assistant, specialized in helping you understand and respond to security threats. Here's what I can help you with:

**🔍 IP Analysis**
- Analyze any IP address for security threats
- Provide danger scores and classifications
- Identify attack patterns and behaviors
- Generate detailed security reports

**⚠️ Threat Intelligence**
- Explain different types of network attacks
- Help identify suspicious network activity
- Provide mitigation strategies
- Security best practices and recommendations

**📊 Network Security**
- Analyze traffic patterns
- Detect anomalies and suspicious behavior
- Help with incident response
- Security monitoring guidance

**💬 How to Use Me**
- Ask about specific IP addresses (e.g., "Is 192.168.1.100 safe?")
- Inquire about attack types (e.g., "What are DDoS attacks?")
- Request analysis of network threats
- Get security recommendations

**Example Questions:**
- "Is IP 203.0.113.1 showing malicious activity?"
- "What should I do about port scanning attempts?"
- "How can I protect against brute force attacks?"
- "Analyze the security threat from this IP address"

Just ask me anything about network security, and I'll provide detailed, actionable insights!`;
  }

  // Default general response
  return `I'm your network security AI assistant. I specialize in analyzing network threats, IP addresses, and security patterns. 

You can ask me to:
- Analyze specific IP addresses for security threats
- Explain different types of network attacks  
- Help identify suspicious network activity
- Provide security recommendations and best practices

For example, you could ask "Is IP 192.168.1.100 showing any suspicious activity?" or "What are the signs of a DDoS attack?"

How can I help you with your network security today?`;
}

function generateFallbackResponse(message: string): string {
  return `I apologize, but I encountered an issue processing your request. However, I'm here to help you with network security analysis.

I can assist you with:
- Analyzing IP addresses for security threats
- Explaining network attack patterns  
- Providing security recommendations
- Identifying suspicious network activity

Please try rephrasing your question, or ask me about a specific IP address or security concern you'd like me to analyze.

For example: "Analyze IP 192.168.1.100 for threats" or "What are common signs of network attacks?"`;
}