"use client";

import { useState, useEffect, useRef } from "react";
import { Send, Trash2, MessageSquare, Bot, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

interface Message {
  id: string;
  content: string;
  role: "user" | "assistant";
  timestamp: Date;
}

interface ChatConversation {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
}

export default function AIChatPage() {
  const [conversations, setConversations] = useState<ChatConversation[]>([]);
  const [currentConversation, setCurrentConversation] = useState<ChatConversation | null>(null);
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom when new messages are added
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [currentConversation?.messages]);

  // Load chat history on component mount
  useEffect(() => {
    loadChatHistory();
  }, []);

  const loadChatHistory = async () => {
    try {
      setIsLoadingHistory(true);
      const response = await fetch("/api/chat/conversations");
      if (response.ok) {
        const data = await response.json();
        setConversations(data);
        if (data.length > 0 && !currentConversation) {
          setCurrentConversation(data[0]);
        }
      }
    } catch (error) {
      console.error("Failed to load chat history:", error);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const startNewConversation = () => {
    const newConversation: ChatConversation = {
      id: `conv_${Date.now()}`,
      title: "New Conversation",
      messages: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    setCurrentConversation(newConversation);
  };

  const sendMessage = async () => {
    if (!message.trim() || isLoading) return;

    const userMessage: Message = {
      id: `msg_${Date.now()}`,
      content: message.trim(),
      role: "user",
      timestamp: new Date(),
    };

    // Create a new conversation if none exists
    let conversation = currentConversation;
    if (!conversation) {
      conversation = {
        id: `conv_${Date.now()}`,
        title: message.trim().substring(0, 50) + (message.length > 50 ? "..." : ""),
        messages: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      setCurrentConversation(conversation);
    }

    // Add user message to current conversation
    const updatedConversation = {
      ...conversation,
      messages: [...conversation.messages, userMessage],
      updatedAt: new Date(),
    };
    setCurrentConversation(updatedConversation);
    setMessage("");
    setIsLoading(true);

    try {
      // Send message to AI
      const response = await fetch("/api/chat/message", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: message.trim(),
          conversationId: conversation.id,
          conversationTitle: conversation.title,
          messages: updatedConversation.messages,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        const assistantMessage: Message = {
          id: `msg_${Date.now()}_ai`,
          content: data.response,
          role: "assistant",
          timestamp: new Date(),
        };

        const finalConversation = {
          ...updatedConversation,
          messages: [...updatedConversation.messages, assistantMessage],
          updatedAt: new Date(),
        };

        setCurrentConversation(finalConversation);

        // Reload conversations from database to ensure sync
        await loadChatHistory();
      } else {
        console.error("Failed to send message, status:", response.status);
        
        // Try to get error details from response
        let errorMessage = "Failed to send message";
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          // Ignore JSON parsing errors
        }
        
        // Add error message to conversation
        const errorMessage2: Message = {
          id: `msg_${Date.now()}_error`,
          content: `⚠️ **Error**: ${errorMessage}. Please try again.`,
          role: "assistant",
          timestamp: new Date(),
        };

        const errorConversation = {
          ...updatedConversation,
          messages: [...updatedConversation.messages, errorMessage2],
          updatedAt: new Date(),
        };

        setCurrentConversation(errorConversation);
      }
    } catch (error) {
      console.error("Error sending message:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const deleteConversation = async (conversationId: string) => {
    try {
      const response = await fetch(`/api/chat/conversations/${conversationId}`, {
        method: "DELETE",
      });

      if (response.ok) {
        setConversations(prev => prev.filter(c => c.id !== conversationId));
        if (currentConversation?.id === conversationId) {
          const remaining = conversations.filter(c => c.id !== conversationId);
          setCurrentConversation(remaining.length > 0 ? remaining[0] : null);
        }
      }
    } catch (error) {
      console.error("Failed to delete conversation:", error);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar - Chat History */}
      <div className="w-80 border-r border-border bg-muted/10">
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <MessageSquare className="h-5 w-5" />
              AI Security Chat
            </h2>
            <Button onClick={startNewConversation} size="sm">
              New Chat
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">
            Chat with AI about security attacks, IP threats, and network analysis
          </p>
        </div>

        <ScrollArea className="flex-1 h-[calc(100vh-120px)]">
          <div className="p-4 space-y-2">
            {isLoadingHistory ? (
              <div className="text-center text-muted-foreground py-8">
                Loading chat history...
              </div>
            ) : conversations.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                No conversations yet. Start a new chat!
              </div>
            ) : (
              conversations.map((conversation) => (
                <Card
                  key={conversation.id}
                  className={`cursor-pointer transition-colors ${
                    currentConversation?.id === conversation.id
                      ? "bg-accent border-accent-foreground/20"
                      : "hover:bg-accent/50"
                  }`}
                  onClick={() => setCurrentConversation(conversation)}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {conversation.title}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {conversation.messages.length} messages
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(conversation.updatedAt).toLocaleDateString()}
                        </p>
                      </div>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-8 w-8 p-0 text-muted-foreground hover:text-destructive"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete Conversation</AlertDialogTitle>
                            <AlertDialogDescription>
                              Are you sure you want to delete this conversation? This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => deleteConversation(conversation.id)}
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {currentConversation ? (
          <>
            {/* Chat Header */}
            <div className="border-b border-border p-4">
              <h1 className="text-xl font-semibold">{currentConversation.title}</h1>
              <p className="text-sm text-muted-foreground">
                Ask about security threats, IP analysis, attack patterns, and network security
              </p>
            </div>

            {/* Messages */}
            <ScrollArea className="flex-1 p-4">
              <div className="space-y-4 max-w-4xl mx-auto">
                {currentConversation.messages.length === 0 ? (
                  <div className="text-center py-12">
                    <Bot className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <h3 className="text-lg font-medium mb-2">Start a Conversation</h3>
                    <p className="text-muted-foreground mb-6">
                      Ask me about security threats, suspicious IPs, attack analysis, or any network security questions.
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-2xl mx-auto">
                      <Card className="cursor-pointer hover:bg-accent transition-colors" onClick={() => setMessage("Is IP 192.168.1.100 showing any suspicious activity?")}>
                        <CardContent className="p-4">
                          <p className="text-sm">Is IP 192.168.1.100 showing any suspicious activity?</p>
                        </CardContent>
                      </Card>
                      <Card className="cursor-pointer hover:bg-accent transition-colors" onClick={() => setMessage("What attack patterns should I watch for?")}>
                        <CardContent className="p-4">
                          <p className="text-sm">What attack patterns should I watch for?</p>
                        </CardContent>
                      </Card>
                      <Card className="cursor-pointer hover:bg-accent transition-colors" onClick={() => setMessage("Analyze recent DDoS attacks in my network")}>
                        <CardContent className="p-4">
                          <p className="text-sm">Analyze recent DDoS attacks in my network</p>
                        </CardContent>
                      </Card>
                      <Card className="cursor-pointer hover:bg-accent transition-colors" onClick={() => setMessage("How can I improve my network security?")}>
                        <CardContent className="p-4">
                          <p className="text-sm">How can I improve my network security?</p>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                ) : (
                  currentConversation.messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`flex gap-3 ${
                        msg.role === "user" ? "justify-end" : "justify-start"
                      }`}
                    >
                      {msg.role === "assistant" && (
                        <Avatar className="h-8 w-8 mt-1">
                          <AvatarFallback className="bg-primary text-primary-foreground">
                            <Bot className="h-4 w-4" />
                          </AvatarFallback>
                        </Avatar>
                      )}
                      <div
                        className={`max-w-[70%] rounded-lg p-3 ${
                          msg.role === "user"
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted"
                        }`}
                      >
                        <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                        <p className="text-xs opacity-70 mt-1">
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                      {msg.role === "user" && (
                        <Avatar className="h-8 w-8 mt-1">
                          <AvatarFallback className="bg-secondary">
                            <User className="h-4 w-4" />
                          </AvatarFallback>
                        </Avatar>
                      )}
                    </div>
                  ))
                )}
                {isLoading && (
                  <div className="flex gap-3 justify-start">
                    <Avatar className="h-8 w-8 mt-1">
                      <AvatarFallback className="bg-primary text-primary-foreground">
                        <Bot className="h-4 w-4" />
                      </AvatarFallback>
                    </Avatar>
                    <div className="bg-muted rounded-lg p-3">
                      <div className="flex space-x-1">
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce" />
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: "0.1s" }} />
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: "0.2s" }} />
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>

            {/* Message Input */}
            <div className="border-t border-border p-4">
              <div className="flex gap-2 max-w-4xl mx-auto">
                <Input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Ask about security threats, IP analysis, attacks..."
                  className="flex-1"
                  disabled={isLoading}
                />
                <Button onClick={sendMessage} disabled={!message.trim() || isLoading}>
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <MessageSquare className="h-16 w-16 mx-auto mb-4 text-muted-foreground" />
              <h2 className="text-2xl font-semibold mb-2">AI Security Assistant</h2>
              <p className="text-muted-foreground mb-6 max-w-md">
                Start a new conversation or select an existing one to chat with AI about network security, threats, and analysis.
              </p>
              <Button onClick={startNewConversation}>
                Start New Conversation
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}