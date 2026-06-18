import { Injectable } from '@angular/core';
import Anthropic from '@anthropic-ai/sdk';
import { environment } from '@env/environment';

@Injectable({ providedIn: 'root' })
export class AiSuggestService {

  private client = new Anthropic({ apiKey: environment.anthropicApiKey });

  async suggestDiagnosisCode(clinicalNotes: string): Promise<string> {
    const message = await this.client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 256,
      messages: [
        {
          role: 'user',
          content: `Suggest an ICD-10 code for these clinical notes: ${clinicalNotes}`,
        },
      ],
    });
    const block = message.content[0];
    return block.type === 'text' ? block.text : '';
  }
}
