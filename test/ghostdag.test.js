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

test('ghostdag: honest parallel blocks are all blue', () => {
  const { add } = makeDag(3);
  add('x1', ['g']); add('x2', ['g']); add('x3', ['g']);
  const y = add('y', ['x1', 'x2', 'x3']);
  assert.equal(y.mergesetBlues.length, 3);
  assert.equal(y.mergesetReds.length, 0);
  assert.equal(y.blueScore, 4);
  assert.equal(y.daaScore, 4);
});

test('ghostdag: an attacker\'s secret chain turns red', () => {
  const { add } = makeDag(3);
  let prev = 'g';
  for (let i = 1; i <= 10; i++) { add('h' + i, [prev]); prev = 'h' + i; }
  let a = 'g';
  for (let i = 1; i <= 5; i++) { add('a' + i, [a]); a = 'a' + i; }
  const m = add('m', ['h10', 'a5']);
  assert.equal(m.selectedParent, 'h10');
  assert.deepEqual(m.mergesetBlues, ['h10']);
  assert.equal(m.mergesetReds.length, 5, 'the 5 secret blocks are red');
  assert.equal(m.blueScore, 11);
  assert.equal(m.daaScore, 16, 'but they all count for the DAA (hashrate)');
});

test('ghostdag: an anticone above k turns red even when honest', () => {
  const { add } = makeDag(2);
  // 4 parallel blocks: with k=2 not all of them fit in the blue set
  for (const n of ['p1', 'p2', 'p3', 'p4']) add(n, ['g']);
  const y = add('y', ['p1', 'p2', 'p3', 'p4']);
  assert.equal(y.mergesetBlues.length, 3); // selected parent + 2
  assert.equal(y.mergesetReds.length, 1);
});
