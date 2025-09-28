const path = require('path');

class DirectChatService {
  constructor() {
    // Dynamically require the ChatDatabase with correct path resolution
    const ChatDatabase = require(path.join(process.cwd(), 'server', 'chat-database'));
    this.chatDatabase = new ChatDatabase();
    console.log('DirectChatService: Initialized with chat database');
  }

  async getChatConversations() {
    try {
      return this.chatDatabase.getConversations();
    } catch (error) {
      console.error('Error getting conversations:', error);
      return [];
    }
  }

  async createChatConversation(conversation) {
    try {
      return this.chatDatabase.createConversation(conversation);
    } catch (error) {
      console.error('Error creating conversation:', error);
      return false;
    }
  }

  async insertChatMessage(message) {
    try {
      return this.chatDatabase.insertMessage(message);
    } catch (error) {
      console.error('Error inserting message:', error);
      return false;
    }
  }

  async updateChatConversation(conversationId, updates) {
    try {
      return this.chatDatabase.updateConversation(conversationId, updates);
    } catch (error) {
      console.error('Error updating conversation:', error);
      return false;
    }
  }

  async deleteChatConversation(conversationId) {
    try {
      return this.chatDatabase.deleteConversation(conversationId);
    } catch (error) {
      console.error('Error deleting conversation:', error);
      return false;
    }
  }

  // For IP analysis, we still need to connect to packet database via socket
  // This is a simplified version that returns empty data for now
  async getPackets(options = {}) {
    // For now, return empty array - we can enhance this later
    return [];
  }

  close() {
    if (this.chatDatabase) {
      this.chatDatabase.close();
    }
  }
}

// Export singleton
let directChatService = null;

function getDirectChatService() {
  if (!directChatService) {
    directChatService = new DirectChatService();
  }
  return directChatService;
}

module.exports = { DirectChatService, getDirectChatService };