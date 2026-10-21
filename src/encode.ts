const enc=new TextEncoder();
export const bytes=(s:string)=>enc.encode(s);
export const hex=(a:Uint8Array)=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
/** Domain tag plus 32-bit lengths prevents tuple ambiguity. */
export function tuple(domain:string,...fields:Uint8Array[]):Uint8Array {
 const chunks=[enc.encode(domain),...fields],size=chunks.reduce((n,c)=>n+4+c.length,0),out=new Uint8Array(size),view=new DataView(out.buffer);
 let at=0;for(const chunk of chunks){view.setUint32(at,chunk.length);at+=4;out.set(chunk,at);at+=chunk.length}return out;
}
export const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
export function concat(...parts:Uint8Array[]):Uint8Array {const result=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){result.set(p,at);at+=p.length}return result}

