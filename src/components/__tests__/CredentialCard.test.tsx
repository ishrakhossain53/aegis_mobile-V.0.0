/**
 * CredentialCard component tests
 *
 * Covers:
 *  - Renders title and username
 *  - Shows type label when no username
 *  - Copy button triggers onCopy callback
 *  - SECURITY: never renders plaintext password/passkey/totpSeed/apiKey
 *  - Accessibility label includes type and title
 *  - onPress and onLongPress callbacks fire
 */

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockGetCredential = jest.fn();
const mockGenerateTOTP = jest.fn();
const mockCopy = jest.fn().mockResolvedValue(undefined);

jest.mock('../../services/VaultService', () => ({
  vaultService: {
    getCredential: (...args: unknown[]) => mockGetCredential(...args),
    generateTOTP: (...args: unknown[]) => mockGenerateTOTP(...args),
  },
}));

jest.mock('../../services/SecureClipboardService', () => ({
  secureClipboardService: {
    copy: (...args: unknown[]) => mockCopy(...args),
  },
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import React from 'react';
import { render, fireEvent, act } from '@testing-library/react-native';
import { CredentialCard } from '../CredentialCard';
import { Credential } from '../../types/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCredential(overrides: Partial<Credential> = {}): Credential {
  return {
    id: 'cred-1',
    type: 'password',
    title: 'Gmail',
    username: 'user@gmail.com',
    password: 'super-secret-password',
    tags: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
    favorite: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('CredentialCard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetCredential.mockResolvedValue(makeCredential());
    mockGenerateTOTP.mockResolvedValue({ code: '123456', remainingSeconds: 15 });
  });

  describe('rendering', () => {
    it('renders the credential title', () => {
      const { getByText } = render(<CredentialCard credential={makeCredential()} />);
      expect(getByText('Gmail')).toBeTruthy();
    });

    it('renders the username when present', () => {
      const { getByText } = render(<CredentialCard credential={makeCredential()} />);
      expect(getByText('user@gmail.com')).toBeTruthy();
    });

    it('renders type label when no username', () => {
      const cred = makeCredential({ username: undefined });
      const { getByText } = render(<CredentialCard credential={cred} />);
      expect(getByText('Password')).toBeTruthy();
    });

    it('renders API Key type label for apiKey type', () => {
      const cred = makeCredential({ type: 'apiKey', username: undefined });
      const { getByText } = render(<CredentialCard credential={cred} />);
      expect(getByText('API Key')).toBeTruthy();
    });

    it('renders TOTP type label for totp type', () => {
      const cred = makeCredential({ type: 'totp', username: undefined });
      const { getByText } = render(<CredentialCard credential={cred} />);
      expect(getByText('TOTP')).toBeTruthy();
    });
  });

  describe('SECURITY — never renders sensitive data', () => {
    it('does NOT render the plaintext password in the UI', () => {
      const cred = makeCredential({ password: 'my-plaintext-password-12345' });
      const { queryByText } = render(<CredentialCard credential={cred} />);
      expect(queryByText('my-plaintext-password-12345')).toBeNull();
    });

    it('does NOT render the plaintext apiKey in the UI', () => {
      const cred = makeCredential({ type: 'apiKey', apiKey: 'sk-secret-api-key-xyz' });
      const { queryByText } = render(<CredentialCard credential={cred} />);
      expect(queryByText('sk-secret-api-key-xyz')).toBeNull();
    });

    it('does NOT render the plaintext totpSeed in the UI', () => {
      const cred = makeCredential({ type: 'totp', totpSeed: 'JBSWY3DPEHPK3PXP' });
      const { queryByText } = render(<CredentialCard credential={cred} />);
      expect(queryByText('JBSWY3DPEHPK3PXP')).toBeNull();
    });

    it('does NOT render the plaintext passkey in the UI', () => {
      const cred = makeCredential({ type: 'passkey', passkey: 'passkey-secret-data' });
      const { queryByText } = render(<CredentialCard credential={cred} />);
      expect(queryByText('passkey-secret-data')).toBeNull();
    });
  });

  describe('copy button', () => {
    it('renders the copy button', () => {
      const { getByLabelText } = render(<CredentialCard credential={makeCredential()} />);
      expect(getByLabelText(/Copy Password for Gmail/i)).toBeTruthy();
    });

    it('calls onCopy callback when copy button is pressed', async () => {
      const onCopy = jest.fn();
      const cred = makeCredential();
      const { getByLabelText } = render(
        <CredentialCard credential={cred} onCopy={onCopy} />,
      );

      await act(async () => {
        fireEvent.press(getByLabelText(/Copy Password for Gmail/i));
      });

      expect(onCopy).toHaveBeenCalledWith(cred);
    });

    it('calls SecureClipboardService.copy with the password', async () => {
      const cred = makeCredential({ password: 'the-real-password' });
      mockGetCredential.mockResolvedValue(cred);

      const { getByLabelText } = render(<CredentialCard credential={cred} />);

      await act(async () => {
        fireEvent.press(getByLabelText(/Copy Password for Gmail/i));
      });

      expect(mockCopy).toHaveBeenCalledWith('the-real-password', 'password');
    });

    it('shows checkmark feedback after copy', async () => {
      jest.useFakeTimers();
      const cred = makeCredential();
      const { getByLabelText, getByText } = render(<CredentialCard credential={cred} />);

      await act(async () => {
        fireEvent.press(getByLabelText(/Copy Password for Gmail/i));
      });

      expect(getByText('✓')).toBeTruthy();
      jest.useRealTimers();
    });
  });

  describe('press interactions', () => {
    it('calls onPress when card is tapped', () => {
      const onPress = jest.fn();
      const { getByLabelText } = render(
        <CredentialCard credential={makeCredential()} onPress={onPress} />,
      );
      fireEvent.press(getByLabelText(/Password: Gmail/i));
      expect(onPress).toHaveBeenCalledTimes(1);
    });

    it('calls onLongPress when card is long-pressed', () => {
      const onLongPress = jest.fn();
      const { getByLabelText } = render(
        <CredentialCard
          credential={makeCredential()}
          onLongPress={onLongPress}
        />,
      );
      fireEvent(getByLabelText(/Password: Gmail/i), 'longPress');
      expect(onLongPress).toHaveBeenCalledTimes(1);
    });
  });

  describe('accessibility', () => {
    it('accessibilityLabel includes type and title', () => {
      const { getByLabelText } = render(<CredentialCard credential={makeCredential()} />);
      expect(getByLabelText(/Password: Gmail/i)).toBeTruthy();
    });

    it('accessibilityLabel includes username when present', () => {
      const { getByLabelText } = render(<CredentialCard credential={makeCredential()} />);
      expect(getByLabelText(/user@gmail\.com/i)).toBeTruthy();
    });
  });
});
