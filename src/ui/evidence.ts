import {hex} from '../encode';
export function inspectEvidence(id:string,evidence:unknown){
 const host=document.getElementById(id)!;document.getElementById(id+'-evidence')?.remove();
 const details=document.createElement('details'),summary=document.createElement('summary'),pre=document.createElement('pre');
 summary.textContent='Inspect complete wire and computed evidence (educator view)';
 pre.dataset.evidence=id;pre.textContent=JSON.stringify(evidence,(_key,v)=>v instanceof Uint8Array?hex(v):typeof v==='bigint'?v.toString():v,2);
 pre.tabIndex=0;details.id=id+'-evidence';details.append(summary,pre);host.after(details);
}
