const {test}=require('node:test'),assert=require('node:assert/strict');
const {isPublicMailNode}=require('../dist/index.cjs');
test('public discovery requires an active server NFT stake to the configured factory owner',()=>{
 const stakes=[{receiver:'factory-owner',assets:['node-a','node-b'],revokedAssets:['node-old']}];
 assert.equal(isPublicMailNode('node-a',stakes,'factory-owner'),true);
 assert.equal(isPublicMailNode('node-b',stakes,'factory-owner'),true);
 assert.equal(isPublicMailNode('node-old',stakes,'factory-owner'),false);
 assert.equal(isPublicMailNode('unstaked',stakes,'factory-owner'),false);
 assert.equal(isPublicMailNode('node-a',stakes,'other-owner'),false);
 assert.equal(isPublicMailNode('node-a',[],'factory-owner'),false);
 assert.equal(isPublicMailNode('node-a',[{receiver:'factory-owner',assets:['node-a'],revokedAssets:['node-a']}],'factory-owner'),false);
});
test('token stake or sender allowlist metadata cannot make a node public or hide an active node NFT',()=>{
 assert.equal(isPublicMailNode('node-a',[{receiver:'factory-owner',tokens:[{value:'1000000000000000000'}]}],'factory-owner'),false);
 assert.equal(isPublicMailNode('node-a',[{receiver:'factory-owner',assets:['node-a'],features:['sender-allowlist']}],'factory-owner'),true);
});
