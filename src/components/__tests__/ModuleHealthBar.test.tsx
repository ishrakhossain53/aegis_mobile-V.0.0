/**
 * ModuleHealthBar component tests
 *
 * Covers:
 *  - Renders label and score text
 *  - Score is clamped to 0–100
 *  - Fill color follows green/amber/red thresholds
 *  - onPress callback fires
 *  - Accessibility label is correct
 */

import React from 'react';
import { render, fireEvent } from '@testing-library/react-native';
import { ModuleHealthBar } from '../ModuleHealthBar';

describe('ModuleHealthBar', () => {
  describe('rendering', () => {
    it('renders the label', () => {
      const { getByText } = render(<ModuleHealthBar label="Vault Health" score={80} />);
      expect(getByText('Vault Health')).toBeTruthy();
    });

    it('renders the score as X/100', () => {
      const { getByText } = render(<ModuleHealthBar label="Network Safety" score={65} />);
      expect(getByText('65/100')).toBeTruthy();
    });

    it('clamps score below 0 to 0', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={-10} />);
      expect(getByText('0/100')).toBeTruthy();
    });

    it('clamps score above 100 to 100', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={150} />);
      expect(getByText('100/100')).toBeTruthy();
    });

    it('renders score 0 correctly', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={0} />);
      expect(getByText('0/100')).toBeTruthy();
    });

    it('renders score 100 correctly', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={100} />);
      expect(getByText('100/100')).toBeTruthy();
    });
  });

  describe('color thresholds', () => {
    it('uses green (#00FF88) for score >= 80', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={80} />);
      const scoreText = getByText('80/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#00FF88' })]),
      );
    });

    it('uses amber (#FFB800) for score 50–79', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={65} />);
      const scoreText = getByText('65/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FFB800' })]),
      );
    });

    it('uses red (#FF3B30) for score < 50', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={30} />);
      const scoreText = getByText('30/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FF3B30' })]),
      );
    });

    it('uses green at exactly 80', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={80} />);
      const scoreText = getByText('80/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#00FF88' })]),
      );
    });

    it('uses amber at exactly 50', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={50} />);
      const scoreText = getByText('50/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FFB800' })]),
      );
    });

    it('uses red at exactly 49', () => {
      const { getByText } = render(<ModuleHealthBar label="Test" score={49} />);
      const scoreText = getByText('49/100');
      expect(scoreText.props.style).toEqual(
        expect.arrayContaining([expect.objectContaining({ color: '#FF3B30' })]),
      );
    });
  });

  describe('interaction', () => {
    it('calls onPress when tapped', () => {
      const onPress = jest.fn();
      const { getByRole } = render(
        <ModuleHealthBar label="Vault Health" score={80} onPress={onPress} />,
      );
      fireEvent.press(getByRole('button'));
      expect(onPress).toHaveBeenCalledTimes(1);
    });

    it('renders without onPress (non-interactive)', () => {
      expect(() =>
        render(<ModuleHealthBar label="Test" score={50} />),
      ).not.toThrow();
    });
  });

  describe('accessibility', () => {
    it('has accessibilityRole of button', () => {
      const { getByRole } = render(<ModuleHealthBar label="Test" score={75} />);
      expect(getByRole('button')).toBeTruthy();
    });

    it('accessibilityLabel includes label and score', () => {
      const { getByLabelText } = render(
        <ModuleHealthBar label="Vault Health" score={85} />,
      );
      expect(getByLabelText(/Vault Health: 85 out of 100/i)).toBeTruthy();
    });
  });
});
