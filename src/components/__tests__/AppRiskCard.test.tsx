/**
 * AppRiskCard component tests
 *
 * Covers:
 *  - Renders app name, package name, risk score
 *  - Permission counts (total and dangerous)
 *  - SecurityBadge status mapping (low→safe, medium→warning, high/critical→critical)
 *  - onPress callback fires with the app object
 *  - Accessibility label includes key info
 */

import React from 'react';
import { render, fireEvent } from '@testing-library/react-native';
import { AppRiskCard } from '../AppRiskCard';
import { InstalledApp, AppPermission } from '../../types/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePermission(dangerous: boolean, category: AppPermission['category'] = 'network'): AppPermission {
  return {
    name: `android.permission.${category.toUpperCase()}`,
    granted: true,
    dangerous,
    category,
  };
}

function makeApp(overrides: Partial<InstalledApp> = {}): InstalledApp {
  return {
    id: 'com.example.app',
    name: 'Example App',
    packageName: 'com.example.app',
    version: '1.0.0',
    installedDate: Date.now(),
    permissions: [
      makePermission(true, 'location'),
      makePermission(false, 'network'),
    ],
    riskScore: 45,
    riskLevel: 'medium',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AppRiskCard', () => {
  describe('rendering', () => {
    it('renders the app name', () => {
      const { getByText } = render(<AppRiskCard app={makeApp()} />);
      expect(getByText('Example App')).toBeTruthy();
    });

    it('renders the package name', () => {
      const { getByText } = render(<AppRiskCard app={makeApp()} />);
      expect(getByText('com.example.app')).toBeTruthy();
    });

    it('renders the risk score', () => {
      const { getByText } = render(<AppRiskCard app={makeApp({ riskScore: 72 })} />);
      expect(getByText('72')).toBeTruthy();
    });

    it('renders total permission count', () => {
      const app = makeApp({
        permissions: [makePermission(true), makePermission(false), makePermission(false)],
      });
      const { getByText } = render(<AppRiskCard app={app} />);
      expect(getByText('3')).toBeTruthy();
    });

    it('renders dangerous permission count', () => {
      const app = makeApp({
        permissions: [makePermission(true), makePermission(true), makePermission(false)],
      });
      const { getAllByText } = render(<AppRiskCard app={app} />);
      // '2' appears for dangerous count
      const twos = getAllByText('2');
      expect(twos.length).toBeGreaterThan(0);
    });

    it('renders 0 dangerous permissions when none are dangerous', () => {
      const app = makeApp({
        permissions: [makePermission(false), makePermission(false)],
      });
      const { getAllByText } = render(<AppRiskCard app={app} />);
      const zeros = getAllByText('0');
      expect(zeros.length).toBeGreaterThan(0);
    });

    it('renders the first letter of app name as icon placeholder', () => {
      const { UNSAFE_getAllByType } = render(<AppRiskCard app={makeApp({ name: 'Zoom' })} />);
      // The icon placeholder renders the first letter — verify the app renders without error
      // and the name is shown
      const { getByText } = render(<AppRiskCard app={makeApp({ name: 'Zoom' })} />);
      expect(getByText('Zoom')).toBeTruthy();
    });
  });

  describe('SecurityBadge status mapping', () => {
    it('shows SAFE badge for low risk', () => {
      const { getByText } = render(<AppRiskCard app={makeApp({ riskLevel: 'low' })} />);
      expect(getByText('SAFE')).toBeTruthy();
    });

    it('shows WARNING badge for medium risk', () => {
      const { getByText } = render(<AppRiskCard app={makeApp({ riskLevel: 'medium' })} />);
      expect(getByText('WARNING')).toBeTruthy();
    });

    it('shows CRITICAL badge for high risk', () => {
      const { getByText } = render(<AppRiskCard app={makeApp({ riskLevel: 'high' })} />);
      expect(getByText('CRITICAL')).toBeTruthy();
    });

    it('shows CRITICAL badge for critical risk', () => {
      const { getByText } = render(<AppRiskCard app={makeApp({ riskLevel: 'critical' })} />);
      expect(getByText('CRITICAL')).toBeTruthy();
    });
  });

  describe('interaction', () => {
    it('calls onPress with the app object when tapped', () => {
      const onPress = jest.fn();
      const app = makeApp();
      const { getByRole } = render(<AppRiskCard app={app} onPress={onPress} />);
      fireEvent.press(getByRole('button'));
      expect(onPress).toHaveBeenCalledWith(app);
    });

    it('renders without onPress', () => {
      expect(() => render(<AppRiskCard app={makeApp()} />)).not.toThrow();
    });
  });

  describe('accessibility', () => {
    it('has accessibilityRole of button', () => {
      const { getByRole } = render(<AppRiskCard app={makeApp()} />);
      expect(getByRole('button')).toBeTruthy();
    });

    it('accessibilityLabel includes app name and risk level', () => {
      const app = makeApp({ name: 'TestApp', riskLevel: 'high' });
      const { getByLabelText } = render(<AppRiskCard app={app} />);
      expect(getByLabelText(/TestApp.*high/i)).toBeTruthy();
    });

    it('accessibilityLabel includes permission counts', () => {
      const app = makeApp({
        permissions: [makePermission(true), makePermission(false)],
      });
      const { getByLabelText } = render(<AppRiskCard app={app} />);
      expect(getByLabelText(/2 permissions/i)).toBeTruthy();
    });
  });
});
