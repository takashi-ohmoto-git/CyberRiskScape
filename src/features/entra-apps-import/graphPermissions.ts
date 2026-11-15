import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * Microsoft Graph の「強い権限」の一覧（`data/finding-maps/graph-permissions.yaml`）のスキーマとローダー。
 * DOM にも Node にも依存しない。
 */

/** GUID の形（版の桁は問わない。Microsoft Graph のアプリ ID は RFC 4122 の版の形ではない）。 */
const Guid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

const GraphPermissionsSchema = z.object({
  schemaVersion: z.literal(1),
  microsoftTenantIds: z.array(Guid),
  graphAppId: Guid,
  powerfulPermissions: z.array(z.object({ group: z.string().min(1), names: z.array(z.string().min(1)).nonempty() })),
});

export interface GraphPermissionMap {
  microsoftTenantIds: ReadonlySet<string>;
  graphAppId: string;
  /** 権限の名前 → 分類名。 */
  powerful: ReadonlyMap<string, string>;
}

export function loadGraphPermissions(text: string): GraphPermissionMap {
  const parsed = GraphPermissionsSchema.parse(parseYaml(text));
  const powerful = new Map<string, string>();
  for (const g of parsed.powerfulPermissions) {
    for (const n of g.names) {
      if (powerful.has(n)) throw new Error(`権限の名前が重複しています: ${n}`);
      powerful.set(n, g.group);
    }
  }
  return {
    microsoftTenantIds: new Set(parsed.microsoftTenantIds.map((t) => t.toLowerCase())),
    graphAppId: parsed.graphAppId.toLowerCase(),
    powerful,
  };
}

const sources = import.meta.glob<string>('../../../data/finding-maps/graph-permissions.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_GRAPH_PERMISSIONS: GraphPermissionMap = loadGraphPermissions(
  Object.values(sources)[0] ??
    'schemaVersion: 1\nmicrosoftTenantIds: []\ngraphAppId: 00000003-0000-0000-c000-000000000000\npowerfulPermissions: []\n',
);
