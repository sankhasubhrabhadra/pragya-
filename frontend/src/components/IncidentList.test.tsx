import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import IncidentList from './IncidentList';

describe('IncidentList', () => {
  const mockIncidents = [
    { id: 'INC-1', severity: 'critical', risk_score: 90, events: [] },
    { id: 'INC-2', severity: 'low', risk_score: 10, events: [] }
  ] as any;

  it('renders severity badges correctly', () => {
    render(<IncidentList incidents={mockIncidents} selectedId={null} onSelect={() => {}} />);
    
    const criticalBadge = screen.getByText('critical');
    expect(criticalBadge).toBeInTheDocument();
    expect(criticalBadge.className).toContain('text-red-400');
    
    const lowBadge = screen.getByText('low');
    expect(lowBadge).toBeInTheDocument();
    expect(lowBadge.className).toContain('text-blue-400');
  });
});
