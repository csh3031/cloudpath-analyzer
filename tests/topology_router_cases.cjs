const test=require('node:test');const assert=require('node:assert/strict');
const {routeOrthogonal,svgPath}=require('./orthogonal_router.js');
const box=(x,y,w=40,h=40)=>({x,y,w,h});
const r=(source,target,obstacles=[],extra={})=>routeOrthogonal({source,target,obstacles,...extra});
function check(result,obstacles=[],gap=12){assert.equal(result.status,'routed');assert.ok(result.points.length>=2);for(let i=1;i<result.points.length;i++){const a=result.points[i-1],b=result.points[i];assert.ok(a.x===b.x||a.y===b.y);for(const q of obstacles){const l=q.x-gap,t=q.y-gap,rr=q.x+q.w+gap,bb=q.y+q.h+gap;if(a.x===b.x)assert.ok(!(a.x>l&&a.x<rr&&Math.max(a.y,b.y)>t&&Math.min(a.y,b.y)<bb));else assert.ok(!(a.y>t&&a.y<bb&&Math.max(a.x,b.x)>l&&Math.min(a.x,b.x)<rr));}}}
function on(p,b){return ((p.x===b.x||p.x===b.x+b.w)&&p.y>=b.y&&p.y<=b.y+b.h)||((p.y===b.y||p.y===b.y+b.h)&&p.x>=b.x&&p.x<=b.x+b.w);}
test('straight horizontal and boundary anchors',()=>{let a=box(0,0),b=box(150,0),p=r(a,b);check(p);assert.equal(p.points.length,2);assert.ok(on(p.points[0],a));assert.ok(on(p.points.at(-1),b));});
test('straight vertical',()=>{let p=r(box(0,0),box(0,150));check(p);assert.equal(p.points.length,2);});
test('diagonal uses orthogonal segments',()=>check(r(box(0,0),box(150,150))));
test('solid resource in direct path',()=>{let o=[box(80,-10,50,60)],p=r(box(0,0),box(190,0),o);check(p,o);assert.ok(p.points.length>=4);});
test('unrelated large group is solid obstacle',()=>{let o=[box(90,-80,100,200)];check(r(box(0,0),box(240,0),o),o);});
test('multiple obstacles',()=>{let o=[box(80,-30,40,100),box(150,30,40,100),box(220,-60,40,120)];check(r(box(0,0),box(330,70),o),o);});
test('no clear source port fails closed',()=>{let p=r(box(0,0),box(150,0),[box(-30,-30,100,100)]);assert.equal(p.status,'unrouted');assert.equal(svgPath(p),'');});
test('bounded canvas separated by wall fails closed',()=>{let p=r(box(10,40),box(250,40),[box(130,0,30,150)],{bounds:box(0,0,300,150)});assert.equal(p.status,'unrouted');assert.equal(p.reason,'no_path');});
test('bounded route stays inside canvas',()=>{let p=r(box(20,20),box(180,20),[box(90,0,40,60)],{bounds:box(0,0,250,150)});check(p,[box(90,0,40,60)]);assert.ok(p.points.every(q=>q.x>=0&&q.x<=250&&q.y>=0&&q.y<=150));});
test('overlapping endpoints fail closed',()=>assert.equal(r(box(0,0),box(0,0)).status,'unrouted'));
test('invalid geometry and grid cap',()=>{assert.equal(r(box(0,0,-1,20),box(100,0)).reason,'invalid_geometry');assert.equal(r(box(0,0),box(100,0),[],{maxGridPoints:1}).reason,'grid_limit');});
test('SVG output and deterministic repeat',()=>{const p=r(box(0,0),box(160,100));assert.equal(svgPath(p),svgPath(r(box(0,0),box(160,100))));assert.match(svgPath(p),/^M /);});
test('custom clearance and fractional geometry',()=>{const o=[box(80.5,-10.5,50,60)],p=r(box(0.5,0.5),box(190.5,0.5),o,{clearance:8});check(p,o,8);});
test('drag: recalculates for changed obstacle coordinates',()=>{let a=box(0,0),b=box(200,0),before=r(a,b,[box(90,100)]),after=r(a,b,[box(90,0)]);assert.notEqual(svgPath(before),svgPath(after));check(after,[box(90,0)]);});
