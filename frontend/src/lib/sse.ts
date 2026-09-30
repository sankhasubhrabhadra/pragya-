// A simple SSE parser for fetch ReadableStream
export async function* parseSSE(stream: ReadableStream<Uint8Array>) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      
      const lines = buffer.split('\n');
      buffer = lines.pop() || ''; // Keep the incomplete line in the buffer

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('data: ')) {
          const dataStr = line.slice(6);
          try {
            if (dataStr) yield JSON.parse(dataStr);
          } catch (err) {
            console.error('Failed to parse SSE data chunk:', dataStr, err);
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}
