import { NextRequest, NextResponse } from 'next/server';
import { io } from 'socket.io-client';

export async function POST(request: NextRequest) {
  try {
    const { message, conversationId, conversationTitle } = await request.json();
    console.log('Simple message API called with:', { message, conversationId, conversationTitle });

    return new Promise<NextResponse>((resolve) => {
      const socket = io('http://localhost:3001');
      let stepCompleted = false;

      socket.on('connect', () => {
        console.log('Socket connected, checking conversations...');
        socket.emit('get-chat-conversations');
      });

      socket.on('chat-conversations-data', (conversations: any[]) => {
        console.log('Received conversations:', conversations.length);
        const conversationExists = conversations.some((c: any) => c.id === conversationId);
        
        if (!conversationExists) {
          console.log('Creating new conversation...');
          const conversationData = {
            id: conversationId,
            title: conversationTitle || message.trim().substring(0, 50),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          };
          
          socket.emit('create-chat-conversation', conversationData);
        } else {
          console.log('Conversation exists, saving message...');
          saveMessage();
        }
      });

      socket.on('chat-conversation-created', (success: boolean) => {
        console.log('Conversation created:', success);
        if (success) {
          saveMessage();
        } else {
          socket.disconnect();
          resolve(NextResponse.json({ error: 'Failed to create conversation' }, { status: 500 }));
        }
      });

      function saveMessage() {
        if (stepCompleted) return;
        stepCompleted = true;
        
        console.log('Saving user message...');
        const userMessageData = {
          id: `msg_${Date.now()}_user`,
          conversationId,
          content: message,
          role: 'user',
          timestamp: new Date().toISOString(),
        };

        socket.emit('insert-chat-message', userMessageData);
      }

      socket.on('chat-message-inserted', (success: boolean) => {
        console.log('Message inserted:', success);
        if (success) {
          // Simple AI response
          const aiResponse = `Hello! You said: "${message}". I'm your network security AI assistant. How can I help you with security analysis today?`;
          
          const aiMessageData = {
            id: `msg_${Date.now()}_ai`,
            conversationId,
            content: aiResponse,
            role: 'assistant',
            timestamp: new Date().toISOString(),
          };

          socket.emit('insert-chat-message', aiMessageData);
        } else {
          socket.disconnect();
          resolve(NextResponse.json({ error: 'Failed to save message' }, { status: 500 }));
        }
      });

      let messageCount = 0;
      socket.on('chat-message-inserted', (success: boolean) => {
        messageCount++;
        console.log(`Message ${messageCount} inserted:`, success);
        
        if (messageCount === 2) { // Both user and AI messages saved
          socket.disconnect();
          resolve(NextResponse.json({ 
            response: `Hello! You said: "${message}". I'm your network security AI assistant. How can I help you with security analysis today?`
          }));
        }
      });

      socket.on('connect_error', (error: any) => {
        console.error('Connection error:', error);
        socket.disconnect();
        resolve(NextResponse.json({ error: 'Connection failed' }, { status: 500 }));
      });

      setTimeout(() => {
        console.log('API timeout reached');
        socket.disconnect();
        resolve(NextResponse.json({ error: 'Timeout' }, { status: 500 }));
      }, 10000);
    });
  } catch (error) {
    console.error('Error in simple message API:', error);
    return NextResponse.json({ error: 'Failed to process message' }, { status: 500 });
  }
}