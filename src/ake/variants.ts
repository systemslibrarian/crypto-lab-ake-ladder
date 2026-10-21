export type Definition={id:number;name:string;omitC?:boolean;omitR?:boolean;omitIdP?:boolean;payload:'key-id'|'key'|'key-r';ctr?:boolean;class:'honest'|'key exposure'|'replay'|'identity misbinding'};
export const HONEST:Definition={id:0,name:'AKE1 — all fields restored',payload:'key-id',class:'honest'};
export const VARIANTS:readonly Definition[]=[
 {id:1,name:'V1 · do not sign c',omitC:true,payload:'key-id',class:'key exposure'},
 {id:2,name:'V2 · do not sign r',omitR:true,payload:'key-id',class:'replay'},
 {id:3,name:'V3 · do not sign idP',omitIdP:true,payload:'key-id',class:'identity misbinding'},
 {id:4,name:'V4 · do not encrypt idQ',payload:'key',class:'replay'},
 {id:5,name:'V5 · encrypt r instead of idQ',payload:'key-r',class:'identity misbinding'},
 {id:6,name:'V6 · replace authenticated encryption with CTR',payload:'key-id',ctr:true,class:'replay'},
];
// [extension] point: STS, AKE3, and an HSM signing-oracle model are separate protocol definitions.

