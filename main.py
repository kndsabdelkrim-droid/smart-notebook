1) في vX(): إزالة عمود المستوى وكتابة نوع الفترة (اللغة والمستوى يبقيان في السطر العلوي فقط)

استبدل:

js
tl=blkT(b)?`<tr><th colspan="${b.sl.length+1}" style="background:#f6efd8;color:#000">${blkT(b)} — ${b.lv.map(v=>esc(v.n)).join(' + ')}</th></tr>`:'',
rows=b.lv.map(v=>`<tr><td class="dy">${esc(v.n)}</td>`+b.sl.map(x=>{

بـ:

js
tl=`<tr><th colspan="${b.sl.length}" style="background:#f6efd8;color:#000">${b.lv.map(v=>esc(v.n)).join(' + ')}</th></tr>`,
rows=b.lv.map(v=>`<tr>`+b.sl.map(x=>{

واستبدل:

js
<tr><th rowspan="2">المستوى</th>${h1}</tr><tr>${h2}</tr>

بـ:

js
<tr>${h1}</tr><tr>${h2}</tr>

واستبدل في سطر الترويسة:

js
colspan="${b.sl.length+1}">${GH().replace('جدول الحراسة للامتحان','جدول الامتحانات')}

بـ:

js
colspan="${b.sl.length}">${GH().replace('جدول الحراسة للامتحان','جدول الامتحانات')}

2) تكبير الجدول في المعاينة والطباعة

في ثابت PFS استبدل:

js
const PFS='#v .noprint{display:none!important}#v .pv{display:inline!important}#v .sc td,#v .sc th{padding:3px 5px!important;line-height:normal!important;font-size:14px!important}

بـ:

js
const PFS='#v .noprint{display:none!important}#v .pv{display:inline!important}#v .sc td,#v .sc th{padding:3px 5px!important;line-height:normal!important;font-size:14px!important}#v .sc table.ex td,#v .sc table.ex th{padding:12px 8px!important;font-size:19px!important;font-weight:700}#v .sc table.ex td{min-width:0!important}

وفي fit() ارفع ارتفاع الجدول المتاح لحالة cur==='X'، فاستبدل:

js
Hv=land?690:1000,zw=ts.map

بـ:

js
Hv=land?760:1100,zw=ts.map
