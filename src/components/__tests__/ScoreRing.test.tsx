/**
 * ScoreRing component tests
 *
 * Covers:
 *  - Renders the score value
 *  - Clamps score to 0–100
 *  - Color thresholds (green/amber/red)
 *  - Accessibility attributes
 *  - Custom size and strokeWidth props
 */

import React from 'react';
import { render } from '@testing-library/react-native';
import { ScoreRing } from '../ScoreRing';

// Mock Animated to avoid timer issues in tests
jest.mock('react-native', () => {
  const RN = jest.requireActual('react-native');
  RN.Animated.timing = jest.fn(() => ({ start: jest.fn() }));
  return RN;
});

describe('ScoreRing', () => {
  describe('rendering', () => {
    it('renders the score value', () => {
      const { getByText } = render(<ScoreRing score={75} />);
      expect(getByText('75')).toBeTruthy();
    });

    it('renders score 0', () => {
      const { getByText } = render(<ScoreRing score={0} />);
      expect(getByText('0')).toBeTruthy();
    });

    it('renders score 100', () => {
      const { getByText } = render(<ScoreRing score={100} />);
      expect(getByText('100')).toBeTruthy();
    });

    it('clamps score below 0 to 0', () => {
      const { getByText } = render(<ScoreRing score={-5} />);
      expect(getByText('0')).toBeTruthy();
    });

    it('clamps score above 100 to 100', () => {
      const { getByText } = render(<ScoreRing score={150} />);
      expect(getByText('100')).toBeTruthy();
    });
  });

  describe('color thresholds', () => {
    it('uses green (#00FF88) for score >= 80', () => {
      const { getByText } = render(<ScoreRing score={85} />);
      const scoreText = getByText('85');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#00FF88' })]),
      );
    });

    it('uses amber (#FFB800) for score 50–79', () => {
      const { getByText } = render(<ScoreRing score={65} />);
      const scoreText = getByText('65');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FFB800' })]),
      );
    });

    it('uses red (#FF3B30) for score < 50', () => {
      const { getByText } = render(<ScoreRing score={30} />);
      const scoreText = getByText('30');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FF3B30' })]),
      );
    });

    it('uses green at exactly 80', () => {
      const { getByText } = render(<ScoreRing score={80} />);
      const scoreText = getByText('80');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#00FF88' })]),
      );
    });

    it('uses amber at exactly 50', () => {
      const { getByText } = render(<ScoreRing score={50} />);
      const scoreText = getByText('50');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FFB800' })]),
      );
    });
  });

  describe('accessibility', () => {
    it('has accessibilityRole of progressbar set on the container', () => {
      const { getByLabelText } = render(<ScoreRing score={75} />);
      const ring = getByLabelText('Security score: 75 out of 100');
      expect(ring.props.accessibilityRole).toBe('progressbar');
    });

    it('accessibilityLabel includes the score', () => {
      const { getByLabelText } = render(<ScoreRing score={82} />);
      expect(getByLabelText(/82 out of 100/i)).toBeTruthy();
    });

    it('accessibilityValue has correct min, max, now', () => {
      const { getByLabelText } = render(<ScoreRing score={60} />);
      const ring = getByLabelText('Security score: 60 out of 100');
      expect(ring.props.accessibilityValue).toEqual({ min: 0, max: 100, now: 60 });
    });
  });

  describe('props', () => {
    it('accepts custom size prop', () => {
      expect(() => render(<ScoreRing score={50} size={200} />)).not.toThrow();
    });

    it('accepts custom strokeWidth prop', () => {
      expect(() => render(<ScoreRing score={50} strokeWidth={15} />)).not.toThrow();
    });

    it('accepts style prop', () => {
      expect(() =>
        render(<ScoreRing score={50} style={{ marginTop: 16 }} />),
      ).not.toThrow();
    });
  });
});
