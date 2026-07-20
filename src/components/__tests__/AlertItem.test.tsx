/**
 * AlertItem component tests
 *
 * Covers:
 *  - Renders description and timestamp
 *  - Severity badge shows correct label
 *  - Dismiss button calls onDismiss with correct ID
 *  - Resolved alerts show RESOLVED badge and no dismiss button
 *  - Accessibility label includes severity and description
 *  - appName is shown when present
 */

import React from 'react';
import { render, fireEvent } from '@testing-library/react-native';
import { AlertItem } from '../AlertItem';
import { Threat } from '../../types/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 'threat-1',
    type: 'suspicious_network',
    severity: 'high',
    description: 'Suspicious network activity detected',
    detectedAt: new Date('2024-01-15T10:00:00Z').getTime(),
    resolved: false,
    metadata: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AlertItem', () => {
  describe('rendering', () => {
    it('renders the threat description', () => {
      const { getByText } = render(<AlertItem threat={makeThreat()} />);
      expect(getByText('Suspicious network activity detected')).toBeTruthy();
    });

    it('renders the severity badge in uppercase', () => {
      const { getByText } = render(<AlertItem threat={makeThreat({ severity: 'critical' })} />);
      expect(getByText('CRITICAL')).toBeTruthy();
    });

    it('renders HIGH severity badge', () => {
      const { getByText } = render(<AlertItem threat={makeThreat({ severity: 'high' })} />);
      expect(getByText('HIGH')).toBeTruthy();
    });

    it('renders MEDIUM severity badge', () => {
      const { getByText } = render(<AlertItem threat={makeThreat({ severity: 'medium' })} />);
      expect(getByText('MEDIUM')).toBeTruthy();
    });

    it('renders LOW severity badge', () => {
      const { getByText } = render(<AlertItem threat={makeThreat({ severity: 'low' })} />);
      expect(getByText('LOW')).toBeTruthy();
    });

    it('renders appName when provided', () => {
      const { getByText } = render(
        <AlertItem threat={makeThreat({ appName: 'SuspiciousApp' })} />,
      );
      expect(getByText('App: SuspiciousApp')).toBeTruthy();
    });

    it('does not render appName when not provided', () => {
      const { queryByText } = render(<AlertItem threat={makeThreat()} />);
      expect(queryByText(/App:/)).toBeNull();
    });
  });

  describe('dismiss button', () => {
    it('renders dismiss button when onDismiss is provided and threat is not resolved', () => {
      const onDismiss = jest.fn();
      const { getByText } = render(
        <AlertItem threat={makeThreat()} onDismiss={onDismiss} />,
      );
      expect(getByText('Dismiss')).toBeTruthy();
    });

    it('calls onDismiss with the threat ID when pressed', () => {
      const onDismiss = jest.fn();
      const { getByText } = render(
        <AlertItem threat={makeThreat({ id: 'threat-abc' })} onDismiss={onDismiss} />,
      );
      fireEvent.press(getByText('Dismiss'));
      expect(onDismiss).toHaveBeenCalledWith('threat-abc');
    });

    it('does not render dismiss button when onDismiss is not provided', () => {
      const { queryByText } = render(<AlertItem threat={makeThreat()} />);
      expect(queryByText('Dismiss')).toBeNull();
    });

    it('does not render dismiss button for resolved threats', () => {
      const onDismiss = jest.fn();
      const { queryByText } = render(
        <AlertItem threat={makeThreat({ resolved: true })} onDismiss={onDismiss} />,
      );
      expect(queryByText('Dismiss')).toBeNull();
    });
  });

  describe('resolved state', () => {
    it('shows RESOLVED badge for resolved threats', () => {
      const { getByText } = render(
        <AlertItem threat={makeThreat({ resolved: true })} />,
      );
      expect(getByText('RESOLVED')).toBeTruthy();
    });

    it('does not show RESOLVED badge for unresolved threats', () => {
      const { queryByText } = render(
        <AlertItem threat={makeThreat({ resolved: false })} />,
      );
      expect(queryByText('RESOLVED')).toBeNull();
    });
  });

  describe('accessibility', () => {
    it('has accessibilityRole of alert set on the container', () => {
      const threat = makeThreat();
      const { getByLabelText } = render(<AlertItem threat={threat} />);
      const el = getByLabelText(/HIGH alert/i);
      expect(el.props.accessibilityRole).toBe('alert');
    });

    it('accessibilityLabel includes severity and description', () => {
      const threat = makeThreat({ severity: 'high', description: 'Test threat' });
      const { getByLabelText } = render(<AlertItem threat={threat} />);
      const element = getByLabelText(/HIGH alert: Test threat/i);
      expect(element).toBeTruthy();
    });

    it('accessibilityLabel includes Resolved for resolved threats', () => {
      const threat = makeThreat({ resolved: true });
      const { getByLabelText } = render(<AlertItem threat={threat} />);
      const element = getByLabelText(/Resolved/i);
      expect(element).toBeTruthy();
    });
  });
});
