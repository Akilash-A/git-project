const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class ChatDatabase {
  constructor() {
    // Create database directory if it doesn't exist
    const dbDir = path.join(__dirname, '../data');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    
    // Initialize chat database
    this.db = new Database(path.join(dbDir, 'chat.db'));
    this.initializeTables();
    
    console.log('✓ Chat Database initialized successfully');
  }

  initializeTables() {
    // Create chat conversations table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS chat_conversations (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create chat messages table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        content TEXT NOT NULL,
        role TEXT NOT NULL, -- 'user' or 'assistant'
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
      )
    `);

    // Create indexes for better performance
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_id ON chat_messages(conversation_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_chat_conversations_updated_at ON chat_conversations(updated_at)`);
  }

  // Chat operations
  createConversation(conversation) {
    const stmt = this.db.prepare(`
      INSERT INTO chat_conversations (id, title, created_at, updated_at)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(
      conversation.id,
      conversation.title,
      conversation.createdAt,
      conversation.updatedAt
    );
    return result.changes > 0;
  }

  insertMessage(message) {
    const stmt = this.db.prepare(`
      INSERT INTO chat_messages (id, conversation_id, content, role, timestamp)
      VALUES (?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      message.id,
      message.conversationId,
      message.content,
      message.role,
      message.timestamp
    );
    return result.changes > 0;
  }

  getConversations() {
    const conversationsStmt = this.db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM chat_conversations
      ORDER BY updated_at DESC
    `);
    const conversations = conversationsStmt.all();

    // Get messages for each conversation
    const messagesStmt = this.db.prepare(`
      SELECT id, content, role, timestamp
      FROM chat_messages
      WHERE conversation_id = ?
      ORDER BY timestamp ASC
    `);

    return conversations.map(conv => ({
      id: conv.id,
      title: conv.title,
      createdAt: new Date(conv.created_at),
      updatedAt: new Date(conv.updated_at),
      messages: messagesStmt.all(conv.id).map(msg => ({
        id: msg.id,
        content: msg.content,
        role: msg.role,
        timestamp: new Date(msg.timestamp)
      }))
    }));
  }

  getConversation(conversationId) {
    const conversationStmt = this.db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM chat_conversations
      WHERE id = ?
    `);
    const conversation = conversationStmt.get(conversationId);

    if (!conversation) return null;

    const messagesStmt = this.db.prepare(`
      SELECT id, content, role, timestamp
      FROM chat_messages
      WHERE conversation_id = ?
      ORDER BY timestamp ASC
    `);

    return {
      id: conversation.id,
      title: conversation.title,
      createdAt: new Date(conversation.created_at),
      updatedAt: new Date(conversation.updated_at),
      messages: messagesStmt.all(conversationId).map(msg => ({
        id: msg.id,
        content: msg.content,
        role: msg.role,
        timestamp: new Date(msg.timestamp)
      }))
    };
  }

  updateConversation(conversationId, updates) {
    const fields = [];
    const values = [];

    if (updates.title) {
      fields.push('title = ?');
      values.push(updates.title);
    }
    if (updates.updatedAt) {
      fields.push('updated_at = ?');
      values.push(updates.updatedAt);
    }

    if (fields.length === 0) return false;

    values.push(conversationId);
    const stmt = this.db.prepare(`
      UPDATE chat_conversations 
      SET ${fields.join(', ')}
      WHERE id = ?
    `);
    const result = stmt.run(...values);
    return result.changes > 0;
  }

  deleteConversation(conversationId) {
    // Delete messages first (CASCADE should handle this, but being explicit)
    const deleteMessagesStmt = this.db.prepare(`DELETE FROM chat_messages WHERE conversation_id = ?`);
    deleteMessagesStmt.run(conversationId);

    // Delete conversation
    const deleteConversationStmt = this.db.prepare(`DELETE FROM chat_conversations WHERE id = ?`);
    const result = deleteConversationStmt.run(conversationId);
    return result.changes > 0;
  }

  // Get conversation count
  getConversationCount() {
    const stmt = this.db.prepare(`SELECT COUNT(*) as count FROM chat_conversations`);
    const result = stmt.get();
    return result.count;
  }

  // Get message count
  getMessageCount() {
    const stmt = this.db.prepare(`SELECT COUNT(*) as count FROM chat_messages`);
    const result = stmt.get();
    return result.count;
  }

  // Get recent conversations
  getRecentConversations(limit = 10) {
    const conversationsStmt = this.db.prepare(`
      SELECT id, title, created_at, updated_at
      FROM chat_conversations
      ORDER BY updated_at DESC
      LIMIT ?
    `);
    const conversations = conversationsStmt.all(limit);

    return conversations.map(conv => ({
      id: conv.id,
      title: conv.title,
      createdAt: new Date(conv.created_at),
      updatedAt: new Date(conv.updated_at)
    }));
  }

  // Search conversations by title or message content
  searchConversations(query) {
    const searchStmt = this.db.prepare(`
      SELECT DISTINCT c.id, c.title, c.created_at, c.updated_at
      FROM chat_conversations c
      LEFT JOIN chat_messages m ON c.id = m.conversation_id
      WHERE c.title LIKE ? OR m.content LIKE ?
      ORDER BY c.updated_at DESC
    `);
    
    const searchQuery = `%${query}%`;
    const conversations = searchStmt.all(searchQuery, searchQuery);

    return conversations.map(conv => ({
      id: conv.id,
      title: conv.title,
      createdAt: new Date(conv.created_at),
      updatedAt: new Date(conv.updated_at)
    }));
  }

  // Clear all chat data
  clearAllChatData() {
    const deleteMessages = this.db.prepare(`DELETE FROM chat_messages`);
    const deleteConversations = this.db.prepare(`DELETE FROM chat_conversations`);
    
    deleteMessages.run();
    deleteConversations.run();
    
    return true;
  }

  // Database maintenance
  vacuum() {
    this.db.exec('VACUUM');
  }

  close() {
    this.db.close();
  }
}

module.exports = ChatDatabase;