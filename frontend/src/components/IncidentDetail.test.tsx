import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import IncidentDetail from './IncidentDetail';
import { type IncidentChain } from '../api';

describe('IncidentDetail', () => {
  const mockIncident: IncidentChain = {
    id: 'INC-123',
    risk_score: 95.0,
    severity: 'critical',
    events: [
      {
        event: {
          event_id: 'evt-1',
          timestamp: '2026-09-30T10:00:00Z',
          source: 'auth',
          user: 'Faculty-42',
          source_ip: '10.0.1.55',
          dest_ip: null,
          host: null,
          event_type: 'fail',
          details: '<img src=x onerror=alert(1)>',
          anomaly_score: 0.1
        },
        stage: 'initial_access',
        reason: 'Failed auth'
      }
    ]
  };

  it('renders stages and checks XSS text rendering', () => {
    render(<IncidentDetail incident={mockIncident} activeEventId={null} />);
    
    // Check that the stage is rendered
    expect(screen.getByText('initial access')).toBeInTheDocument();
    
    // The details should be rendered as plain text, not HTML
    // We search for the exact text string of the XSS payload. 
    // If it was rendered as HTML, getByText would not find it because it would be a DOM node.
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  });
});
