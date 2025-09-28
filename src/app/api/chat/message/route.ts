import { NextRequest, NextResponse } from 'next/server';
import { ipAddressSecurityScoring } from '@/ai/flows/ip-address-security-scoring';
import { io } from 'socket.io-client';

export async function POST(request: NextRequest) {
  try {
    const { message, conversationId, messages, conversationTitle } = await request.json();

    // Use a simpler approach - create the conversation and messages using socket.io
    return new Promise<NextResponse>((resolve) => {
      const socket = io('http://localhost:3001');
      let conversationCreated = false;
      let userMessageSaved = false;
      let aiResponse = '';

      socket.on('connect', () => {
        // First check if conversation exists
        socket.emit('get-chat-conversations');
      });

      socket.on('chat-conversations-data', (conversations) => {
        const conversationExists = conversations.some((c: any) => c.id === conversationId);
        
        if (!conversationExists) {
          // Create the conversation first
          const conversationData = {
            id: conversationId,
            title: conversationTitle || message.trim().substring(0, 50) + (message.length > 50 ? "..." : ""),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          };
          
          socket.emit('create-chat-conversation', conversationData);
        } else {
          conversationCreated = true;
          saveUserMessage();
        }
      });

      socket.on('chat-conversation-created', (success) => {
        if (success) {
          conversationCreated = true;
          saveUserMessage();
        } else {
          socket.disconnect();
          resolve(NextResponse.json({ error: 'Failed to create conversation' }, { status: 500 }));
        }
      });

      function saveUserMessage() {
        const userMessageData = {
          id: `msg_${Date.now()}_user`,
          conversationId,
          content: message,
          role: 'user',
          timestamp: new Date().toISOString(),
        };

        socket.emit('insert-chat-message', userMessageData);
      }

      socket.on('chat-message-inserted', (success) => {
        if (success && !userMessageSaved) {
          userMessageSaved = true;
          // Generate AI response
          generateAIResponse();
        } else if (success && userMessageSaved) {
          // AI message saved, we're done
          socket.disconnect();
          resolve(NextResponse.json({ response: aiResponse }));
        }
      });

      async function generateAIResponse() {
        // Simple AI response for now
        aiResponse = `I'm your network security AI assistant. You asked: "${message}"\n\nI can help you with network security analysis, threat detection, and IP address security scoring. How can I assist you further?`;
        
        // Save AI response
        const aiMessageData = {
          id: `msg_${Date.now()}_ai`,
          conversationId,
          content: aiResponse,
          role: 'assistant',
          timestamp: new Date().toISOString(),
        };

        socket.emit('insert-chat-message', aiMessageData);
      }

      socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        socket.disconnect();
        resolve(NextResponse.json({ error: 'Failed to process message' }, { status: 500 }));
      });

      setTimeout(() => {
        socket.disconnect();
        resolve(NextResponse.json({ error: 'Timeout' }, { status: 500 }));
      }, 10000);
    });

    // Save user message to database
    const userMessageData = {
      id: `msg_${Date.now()}_user`,
      conversationId,
      content: message,
      role: 'user',
      timestamp: new Date().toISOString(),
    };

    await chatService.insertChatMessage(userMessageData);

    // Update conversation timestamp
    await chatService.updateChatConversation(conversationId, {
      updatedAt: new Date().toISOString(),
    });

    // Generate AI response based on message content
    let aiResponse = '';
    
    try {
      // Check if the message is asking about IP analysis
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ips = message.match(ipRegex);
      
      if (ips && ips.length > 0) {
        // Use AI to analyze IP
        const ip = ips[0];
        
        // Get packet data for this IP (mock data for now)
        const packets = await chatService.getPackets({ ip, limit: 100 });
        
        // Prepare attack data
        const attackData = {
          totalPackets: packets.length,
          ddosAttacks: packets.filter((p: any) => p.is_ddos_attack).length,
          portScans: packets.filter((p: any) => p.is_port_scan).length,
          bruteForceAttacks: packets.filter((p: any) => p.is_brute_force).length,
          malwareDetections: packets.filter((p: any) => p.is_malware).length,
          connectionFloods: packets.filter((p: any) => p.is_connection_flood).length,
          unauthorizedAccess: packets.filter((p: any) => p.is_unauthorized_access).length,
          knownThreats: packets.filter((p: any) => p.is_known_threat).length,
          averageThreatScore: packets.length > 0 ? packets.reduce((sum: number, p: any) => sum + (p.threat_score || 0), 0) / packets.length : 0,
          maxThreatScore: packets.length > 0 ? Math.max(...packets.map((p: any) => p.threat_score || 0)) : 0,
          attackDetails: packets.filter((p: any) => p.attack_details).map((p: any) => p.attack_details).slice(0, 10)
        };

        const aiResult = await ipAddressSecurityScoring({
          ipAddress: ip,
          attackData
        });

        aiResponse = `## IP Analysis for ${ip}

**Security Classification:** ${aiResult.securityScore}
**Danger Score:** ${aiResult.dangerScore}/100

**Analysis:**
${aiResult.analysisDetails}

**Attack Summary:**
- Total Packets: ${attackData.totalPackets}
- DDoS Attacks: ${attackData.ddosAttacks}
- Port Scans: ${attackData.portScans}
- Brute Force Attempts: ${attackData.bruteForceAttacks}
- Malware Detections: ${attackData.malwareDetections}
- Connection Floods: ${attackData.connectionFloods}
- Unauthorized Access: ${attackData.unauthorizedAccess}
- Known Threats: ${attackData.knownThreats}

**Threat Score:**
- Average: ${attackData.averageThreatScore.toFixed(2)}
- Maximum: ${attackData.maxThreatScore}

${attackData.attackDetails.length > 0 ? `**Recent Attack Details:**\n${attackData.attackDetails.slice(0, 5).map((detail: string) => `- ${detail}`).join('\n')}` : ''}

**Recommendations:**
Based on this analysis, consider implementing enhanced monitoring and security measures for this IP address.`;

      } else if (message.toLowerCase().includes('attack') || message.toLowerCase().includes('threat') || message.toLowerCase().includes('security')) {
        // General security discussion
        aiResponse = await generateSecurityResponse(message, messages);
      } else {
        // General AI assistant response
        aiResponse = await generateGeneralResponse(message, messages);
      }
    } catch (aiError) {
      console.error('AI generation error:', aiError);
      aiResponse = generateFallbackResponse(message);
    }

    // Save AI response to database
    const aiMessageData = {
      id: `msg_${Date.now()}_ai`,
      conversationId,
      content: aiResponse,
      role: 'assistant',
      timestamp: new Date().toISOString(),
    };

    await chatService.insertChatMessage(aiMessageData);

    // Update conversation timestamp again
    await chatService.updateChatConversation(conversationId, {
      updatedAt: new Date().toISOString(),
    });

    return NextResponse.json({ response: aiResponse });
  } catch (error) {
    console.error('Error processing chat message:', error);
    return NextResponse.json(
      { error: 'Failed to process message' },
      { status: 500 }
    );
  }
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