import { NextRequest, NextResponse } from 'next/server';
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

export async function GET() {
  let db: any = null;
  
  try {
    db = getDatabase();
    
    const conversationsStmt = db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM chat_conversations
      ORDER BY updated_at DESC
    `);
    const conversations = conversationsStmt.all();

    // Get messages for each conversation
    const messagesStmt = db.prepare(`
      SELECT id, content, role, timestamp
      FROM chat_messages
      WHERE conversation_id = ?
      ORDER BY timestamp ASC
    `);

    const result = conversations.map((conv: any) => ({
      id: conv.id,
      title: conv.title,
      createdAt: new Date(conv.created_at),
      updatedAt: new Date(conv.updated_at),
      messages: messagesStmt.all(conv.id).map((msg: any) => ({
        id: msg.id,
        content: msg.content,
        role: msg.role,
        timestamp: new Date(msg.timestamp),
      })),
    }));

    db.close();
    return NextResponse.json(result);
    
  } catch (error) {
    console.error('Error fetching conversations:', error);
    if (db) {
      db.close();
    }
    return NextResponse.json({ error: 'Failed to fetch conversations' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  let db: any = null;
  
  try {
    const conversation = await request.json();
    
    // Add timestamps
    const now = new Date().toISOString();
    const conversationData = {
      ...conversation,
      createdAt: now,
      updatedAt: now,
    };

    db = getDatabase();
    
    const createConversationStmt = db.prepare(`
      INSERT INTO chat_conversations (id, title, created_at, updated_at)
      VALUES (?, ?, ?, ?)
    `);
    
    createConversationStmt.run(
      conversationData.id,
      conversationData.title,
      conversationData.createdAt,
      conversationData.updatedAt
    );
    
    db.close();
    return NextResponse.json(conversationData);
    
  } catch (error) {
    console.error('Error creating conversation:', error);
    if (db) {
      db.close();
    }
    return NextResponse.json({ error: 'Failed to create conversation' }, { status: 500 });
  }
}