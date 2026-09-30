import { describe, it, expect } from 'vitest';
import { parseSSE } from './sse';

describe('SSE Parser', () => {
  it('should parse complete JSON chunks', async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('data: {"step": 1}\n\n'));
        controller.enqueue(new TextEncoder().encode('data: {"step": 2}\n\n'));
        controller.close();
      }
    });

    const results = [];
    for await (const data of parseSSE(stream)) {
      results.push(data);
    }

    expect(results).toEqual([{ step: 1 }, { step: 2 }]);
  });

  it('should handle split chunks across the stream', async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('data: {"long_text": "hello '));
        controller.enqueue(new TextEncoder().encode('world"}\n\n'));
        controller.close();
      }
    });

    const results = [];
    for await (const data of parseSSE(stream)) {
      results.push(data);
    }

    expect(results).toEqual([{ long_text: 'hello world' }]);
  });
});
