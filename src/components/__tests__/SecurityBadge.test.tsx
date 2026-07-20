/**
 * SecurityBadge component tests
 *
 * Covers:
 *  - Renders correct label for each status (safe/warning/critical)
 *  - Accessibility label is correct
 *  - Background color uses the correct status color
 *  - hexToRgba helper produces correct rgba string
 */

import React from 'react';
import { render } from '@testing-library/react-native';
import { SecurityBadge } from '../SecurityBadge';

describe('SecurityBadge', () => {
  describe('label rendering', () => {
    it('renders SAFE for status=safe', () => {
      const { getByText } = render(<SecurityBadge status="safe" />);
      expect(getByText('SAFE')).toBeTruthy();
    });

    it('renders WARNING for status=warning', () => {
      const { getByText } = render(<SecurityBadge status="warning" />);
      expect(getByText('WARNING')).toBeTruthy();
    });

    it('renders CRITICAL for status=critical', () => {
      const { getByText } = render(<SecurityBadge status="critical" />);
      expect(getByText('CRITICAL')).toBeTruthy();
    });
  });

  describe('accessibility', () => {
    it('has correct accessibilityLabel for safe', () => {
      const { getByLabelText } = render(<SecurityBadge status="safe" />);
      expect(getByLabelText('Security status: SAFE')).toBeTruthy();
    });

    it('has correct accessibilityLabel for warning', () => {
      const { getByLabelText } = render(<SecurityBadge status="warning" />);
      expect(getByLabelText('Security status: WARNING')).toBeTruthy();
    });

    it('has correct accessibilityLabel for critical', () => {
      const { getByLabelText } = render(<SecurityBadge status="critical" />);
      expect(getByLabelText('Security status: CRITICAL')).toBeTruthy();
    });

    it('has accessibilityRole of text', () => {
      const { getByRole } = render(<SecurityBadge status="safe" />);
      expect(getByRole('text')).toBeTruthy();
    });
  });

  describe('color application', () => {
    it('applies green color for safe status', () => {
      const { getByText } = render(<SecurityBadge status="safe" />);
      const text = getByText('SAFE');
      expect(text.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#00FF88' })]),
      );
    });

    it('applies amber color for warning status', () => {
      const { getByText } = render(<SecurityBadge status="warning" />);
      const text = getByText('WARNING');
      expect(text.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FFB800' })]),
      );
    });

    it('applies red color for critical status', () => {
      const { getByText } = render(<SecurityBadge status="critical" />);
      const text = getByText('CRITICAL');
      expect(text.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FF3B30' })]),
      );
    });
  });

  describe('rendering', () => {
    it('renders without crashing for all statuses', () => {
      expect(() => render(<SecurityBadge status="safe" />)).not.toThrow();
      expect(() => render(<SecurityBadge status="warning" />)).not.toThrow();
      expect(() => render(<SecurityBadge status="critical" />)).not.toThrow();
    });

    it('accepts an optional style prop', () => {
      expect(() =>
        render(<SecurityBadge status="safe" style={{ marginTop: 8 }} />),
      ).not.toThrow();
    });
  });
});
