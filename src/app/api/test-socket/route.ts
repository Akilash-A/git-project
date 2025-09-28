import { NextRequest, NextResponse } from 'next/server';
import { io } from 'socket.io-client';

export async function GET() {
  return new Promise((resolve) => {
    const socket = io('http://localhost:3001');
    
    socket.on('connect', () => {
      console.log('Test: Connected to socket server');
      socket.emit('get-chat-conversations');
    });
    
    socket.on('chat-conversations-data', (conversations) => {
      console.log('Test: Received conversations:', conversations.length);
      socket.disconnect();
      resolve(NextResponse.json(conversations));
    });
    
    socket.on('connect_error', (error) => {
      console.error('Test: Connection error:', error);
      socket.disconnect();
      resolve(NextResponse.json({ error: 'Connection failed', details: error.message }, { status: 500 }));
    });
    
    // Timeout after 5 seconds
    setTimeout(() => {
      socket.disconnect();
      resolve(NextResponse.json({ error: 'Timeout' }, { status: 500 }));
    }, 5000);
  });
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  
  return new Promise((resolve) => {
    const socket = io('http://localhost:3001');
    
    socket.on('connect', () => {
      console.log('Test: Connected for conversation creation');
      socket.emit('create-chat-conversation', body);
    });
    
    socket.on('chat-conversation-created', (success) => {
      console.log('Test: Conversation created:', success);
      socket.disconnect();
      resolve(NextResponse.json({ success }));
    });
    
    socket.on('connect_error', (error) => {
      console.error('Test: Connection error:', error);
      socket.disconnect();
      resolve(NextResponse.json({ error: 'Connection failed', details: error.message }, { status: 500 }));
    });
    
    // Timeout after 5 seconds
    setTimeout(() => {
      socket.disconnect();
      resolve(NextResponse.json({ error: 'Timeout' }, { status: 500 }));
    }, 5000);
  });
}