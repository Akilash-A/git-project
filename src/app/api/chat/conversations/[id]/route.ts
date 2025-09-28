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

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  let db: any = null;
  
  try {
    // Await params to fix Next.js async issue
    const resolvedParams = await params;
    const conversationId = resolvedParams.id;
    
    db = getDatabase();
    
    // Delete messages first (foreign key constraint)
    const deleteMessagesStmt = db.prepare('DELETE FROM chat_messages WHERE conversation_id = ?');
    const messagesResult = deleteMessagesStmt.run(conversationId);
    
    // Delete conversation
    const deleteConversationStmt = db.prepare('DELETE FROM chat_conversations WHERE id = ?');
    const conversationResult = deleteConversationStmt.run(conversationId);
    
    db.close();
    
    console.log(`Deleted conversation ${conversationId}: ${conversationResult.changes} conversation(s), ${messagesResult.changes} message(s)`);
    
    if (conversationResult.changes > 0) {
      return NextResponse.json({ success: true });
    } else {
      return NextResponse.json(
        { error: 'Conversation not found' },
        { status: 404 }
      );
    }
  } catch (error) {
    console.error('Error deleting conversation:', error);
    if (db) {
      db.close();
    }
    return NextResponse.json(
      { error: 'Failed to delete conversation' },
      { status: 500 }
    );
  }
}