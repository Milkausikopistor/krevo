import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DagStore, Ghostdag, genesisGhostdag } from '../src/consensus/ghostdag.js';

function makeDag(k) {
  const store = new DagStore();
  const gd = new Ghostdag(store, k);
  const g = genesisGhostdag(); g.mergesetAsc = [];
  store.add('g', [], g, 1n);
  const add = (name, parents) => { const d = gd.run(parents); store.add(name, parents, d, 1n); return d; };
  return { store, gd, add };
}

test('ghostdag: blocos paralelos honestos são todos azuis', () => {
  const { add } = makeDag(3);
  add('x1', ['g']); add('x2', ['g']); add('x3', ['g']);
  const y = add('y', ['x1', 'x2', 'x3']);
  assert.equal(y.mergesetBlues.length, 3);
  assert.equal(y.mergesetReds.length, 0);
  assert.equal(y.blueScore, 4);
  assert.equal(y.daaScore, 4);
});

test('ghostdag: cadeia secreta de um atacante fica vermelha', () => {
  const { add } = makeDag(3);
  let prev = 'g';
  for (let i = 1; i <= 10; i++) { add('h' + i, [prev]); prev = 'h' + i; }
  let a = 'g';
  for (let i = 1; i <= 5; i++) { add('a' + i, [a]); a = 'a' + i; }
  const m = add('m', ['h10', 'a5']);
  assert.equal(m.selectedParent, 'h10');
  assert.deepEqual(m.mergesetBlues, ['h10']);
  assert.equal(m.mergesetReds.length, 5, 'os 5 blocos secretos são vermelhos');
  assert.equal(m.blueScore, 11);
  assert.equal(m.daaScore, 16, 'mas todos contam para o DAA (hashrate)');
});

test('ghostdag: anticone acima de k vira vermelho mesmo sendo honesto', () => {
  const { add } = makeDag(2);
  // 4 blocos paralelos: com k=2 nem todos cabem no conjunto azul
  for (const n of ['p1', 'p2', 'p3', 'p4']) add(n, ['g']);
  const y = add('y', ['p1', 'p2', 'p3', 'p4']);
  assert.equal(y.mergesetBlues.length, 3); // pai selecionado + 2
  assert.equal(y.mergesetReds.length, 1);
});
