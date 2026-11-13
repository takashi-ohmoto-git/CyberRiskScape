import { describe, expect, it } from 'vitest';
import { BUSINESS_CONTEXT_MAX_ROWS, parseBusinessContextTable } from './parseBusinessContextTable';

const HEADER = 'node,process,cases,value,currency,period,criticality';

describe('parseBusinessContextTable（CSV）', () => {
  it('全列を読み、criticality は大文字小文字を問わず正規化する', () => {
    const r = parseBusinessContextTable(`${HEADER}\nC2,Order-to-Cash,120,5000000,JPY,2026-10,high\n`);
    expect(r).toEqual({
      ok: true,
      rows: [{ node: 'C2', process: 'Order-to-Cash', cases: 120, value: 5000000, currency: 'JPY', period: '2026-10', criticality: 'High' }],
    });
  });

  it('node と process だけの最小の表。BOM・引用符・"" ・CRLF・空行・未知の列を扱う', () => {
    const csv = '﻿process,extra,node\r\n"Pay, then ship ""fast""",x,n1\r\n\r\nB,y,n2\r\n';
    const r = parseBusinessContextTable(csv, 'table.csv');
    expect(r).toEqual({
      ok: true,
      rows: [
        { node: 'n1', process: 'Pay, then ship "fast"' },
        { node: 'n2', process: 'B' },
      ],
    });
  });

  it('必須列の欠落・数値でない値・負の値・不正な criticality は行番号つきのエラー', () => {
    expect(parseBusinessContextTable('node,cases\nC1,1\n')).toMatchObject({ ok: false, error: expect.stringContaining('process') });
    expect(parseBusinessContextTable(`${HEADER}\nC1,P,abc,,,,\n`)).toMatchObject({ ok: false, error: expect.stringContaining('2 行目: cases') });
    expect(parseBusinessContextTable(`${HEADER}\nC1,P,1,,,,\nC2,P,,-5,,,\n`)).toMatchObject({ ok: false, error: expect.stringContaining('3 行目') });
    expect(parseBusinessContextTable(`${HEADER}\nC1,P,,,,,Critical\n`)).toMatchObject({ ok: false, error: expect.stringContaining('2 行目') });
  });

  it('空の表・行数の上限・サイズの上限は拒否する', () => {
    expect(parseBusinessContextTable('')).toMatchObject({ ok: false });
    const many = `node,process\n${Array.from({ length: BUSINESS_CONTEXT_MAX_ROWS + 1 }, () => 'a,b').join('\n')}\n`;
    expect(parseBusinessContextTable(many)).toMatchObject({ ok: false, error: expect.stringContaining('多すぎ') });
    expect(parseBusinessContextTable(`node,process\n${'x'.repeat(5 * 1024 * 1024 + 1)}`)).toMatchObject({ ok: false, error: expect.stringContaining('大きすぎ') });
  });
});

describe('parseBusinessContextTable（JSON）', () => {
  const doc = (rows: unknown[], extra: object = {}) =>
    JSON.stringify({ kind: 'cyberriskscape-business-context', schemaVersion: 1, rows, ...extra });

  it('rows と最上位の source を読む。未知のキーは無視する', () => {
    const r = parseBusinessContextTable(doc([{ node: 'C1', process: 'P', value: 10, zzz: 1 }], { source: { product: 'Celonis', ref: 'km:a/record:b' } }), 't.json');
    expect(r).toEqual({ ok: true, rows: [{ node: 'C1', process: 'P', value: 10 }], source: { product: 'Celonis', ref: 'km:a/record:b' } });
  });

  it('拡張子が無くても先頭が { なら JSON として読む', () => {
    expect(parseBusinessContextTable(doc([{ node: 'C1', process: 'P' }]))).toMatchObject({ ok: true });
  });

  it('kind の違い・壊れた JSON・不正な行は拒否する（行番号つき）', () => {
    expect(parseBusinessContextTable('{"kind":"other","schemaVersion":1,"rows":[]}', 'a.json')).toMatchObject({ ok: false });
    expect(parseBusinessContextTable('{ not json', 'a.json')).toMatchObject({ ok: false });
    expect(parseBusinessContextTable(doc([{ node: 'C1', process: 'P' }, { node: 'C2' }]), 'a.json')).toMatchObject({
      ok: false,
      error: expect.stringContaining('2 行目'),
    });
    expect(parseBusinessContextTable(doc([{ node: 'C1', process: 'P', cases: Number.POSITIVE_INFINITY }]), 'a.json')).toMatchObject({ ok: false });
  });
});
