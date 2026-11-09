import type { AuthType, EncryptionType, NetworkType, TrustLevel } from '../../core/model/types';
import type { TranslationKey } from '../../i18n';

/**
 * DFD LIST（画面）と脅威モデリング報告書（PDF）で共有する、列挙値 → 訳語キーの対応表。
 * 訳語は線・境界のパネルと同じキーを使う。
 */

export const TRUST_LEVEL_KEYS: Record<TrustLevel, TranslationKey> = {
  Internal: 'panels.boundary.trust.internal',
  Partner: 'panels.boundary.trust.partner',
  Internet: 'panels.boundary.trust.internet',
};

export const NETWORK_KEYS: Record<NetworkType, TranslationKey> = {
  Internet: 'panels.edge.network.internet',
  VPN: 'panels.edge.network.vpn',
  VPC: 'panels.edge.network.vpc',
};

export const AUTH_KEYS: Record<AuthType, TranslationKey> = {
  None: 'panels.edge.auth.none',
  Password: 'panels.edge.auth.password',
  ApiKey: 'panels.edge.auth.apiKey',
  Token: 'panels.edge.auth.token',
  MFA: 'panels.edge.auth.mfa',
  Passkey: 'panels.edge.auth.passkey',
  Certificate: 'panels.edge.auth.certificate',
};

/** TLS は線のパネルと同じく訳さず 'TLS 1.2+'。 */
export function encryptionLabel(e: EncryptionType, t: (key: TranslationKey) => string): string {
  if (e === 'Plain') return t('panels.edge.encryption.plain');
  if (e === 'E2EE') return t('panels.edge.encryption.e2ee');
  return 'TLS 1.2+';
}
