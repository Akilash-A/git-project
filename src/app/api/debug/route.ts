import { NextResponse } from 'next/server';
import path from 'path';
import fs from 'fs';

export async function GET() {
  const cwd = process.cwd();
  const serverPath = path.join(cwd, 'server');
  const chatDbPath = path.join(serverPath, 'chat-database.js');
  
  return NextResponse.json({
    cwd,
    serverPath,
    chatDbPath,
    serverExists: fs.existsSync(serverPath),
    chatDbExists: fs.existsSync(chatDbPath),
    serverContents: fs.existsSync(serverPath) ? fs.readdirSync(serverPath) : 'Directory not found'
  });
}