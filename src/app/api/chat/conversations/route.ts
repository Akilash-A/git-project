import { NextRequest, NextResponse } from 'next/server';
import databaseService from '@/lib/database-service';

export async function GET() {
  try {
    const conversations = await databaseService.getChatConversations();
    return NextResponse.json(conversations);
  } catch (error) {
    console.error('Error fetching conversations:', error);
    return NextResponse.json(
      { error: 'Failed to fetch conversations' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const conversation = await request.json();
    
    // Add timestamps
    const now = new Date().toISOString();
    const conversationData = {
      ...conversation,
      createdAt: now,
      updatedAt: now,
    };

    const success = await databaseService.createChatConversation(conversationData);
    
    if (success) {
      return NextResponse.json({ success: true });
    } else {
      return NextResponse.json(
        { error: 'Failed to create conversation' },
        { status: 500 }
      );
    }
  } catch (error) {
    console.error('Error creating conversation:', error);
    return NextResponse.json(
      { error: 'Failed to create conversation' },
      { status: 500 }
    );
  }
}