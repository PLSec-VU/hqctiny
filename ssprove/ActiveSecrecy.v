Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum ssralg.
Set Warnings "notation-overridden,ambiguous-paths".
Unset SsrOldRewriteGoalsOrder.
Open Scope ring_scope.
Import GRing.Theory.

From Stdlib Require Import Utf8.
From extructures Require Import ord fset fmap.
From Equations Require Import Equations.
Require Equations.Prop.DepElim.
Set Equations With UIP.
Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

From HB Require Import structures.

From SSProve.Crypt Require Import NominalPrelude Package Prelude pkg_advantage.
Import PackageNotation.
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

From SSProveHQC Require Import CookieIntegrity MLKEMCCA.

Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
Notation " 'ch ( x ) " := x (at level 2) : package_scope.

Section ActiveSecrecy.

  Context (mlkem_key_bits mlkem_coin_bits auth_bits : nat).
  Context (McPK_t McCt_t : choice_type).
  Context (cookie_key_bits cookie_nonce_bits cookie_bits : nat).
  Context (msg_bits salt_bits reply_nonce_bits session_bits transcript_bits chan_bits : nat).
  Context (HEk_t HSeed_t Theta_t Key_t Tag_t : choice_type).
  Context (Hdr_t ReqSealed_t Payload_t Answer_t HsWire_t AnsWire_t : choice_type).

  #[local] Notation AuthKey := (MlkemKey_t auth_bits).
  #[local] Notation MlkemSeed := (MlkemSeed_t mlkem_key_bits).
  #[local] Notation CookieKey := (CookieKey_t cookie_key_bits).
  #[local] Notation Cookie := (Cookie_t cookie_bits).

  Definition Msg_t := chFin (2 ^ msg_bits).
  Definition Salt_t := chFin (2 ^ salt_bits).
  Definition SessionKey_t := chFin (2 ^ session_bits).
  Definition TransKey_t := chFin (2 ^ transcript_bits).
  Definition ChanKeys_t := chFin (2 ^ chan_bits).
  Definition CookiePlain_t := chProd Theta_t (chProd Msg_t (chProd HSeed_t AuthKey)).
  Definition AuthRef_t := chProd (chOption 'nat) AuthKey.
  Definition SidePlain_t := chProd Theta_t (chProd Msg_t (chProd HSeed_t AuthRef_t)).
  Definition HsReq_t := chProd HEk_t (chProd HSeed_t McCt_t).
  Definition Req_t := chProd Hdr_t (chProd Cookie ReqSealed_t).
  Definition TargetOut_t := chProd McPK_t (chProd McCt_t (chProd ChanKeys_t 'nat)).
  Definition TestIn_t := chProd 'nat Key_t.
  Definition EvalIn_t := chProd 'nat Key_t.

  Context (mlkem_pk : MlkemSeed → McPK_t).
  Context (mlkem_encaps : McPK_t → 'I_(2 ^ mlkem_coin_bits) → McCt_t * AuthKey).
  Context (mlkem_decaps : MlkemSeed → McCt_t → AuthKey).
  Context (fo_derive : HEk_t → Msg_t → Salt_t → Key_t * Theta_t).
  Context (kdf : Key_t → AuthKey → SessionKey_t * TransKey_t).
  Context (chan_keys : AuthKey → ChanKeys_t).
  Context (confirm : TransKey_t → HsReq_t → Salt_t → Tag_t).
  Context (seal_cookie : CookieKey → CookiePlain_t → 'I_(2 ^ cookie_nonce_bits) → Cookie).
  Context (open_cookie : CookieKey → Cookie → option CookiePlain_t).
  Context (seal_hs : ChanKeys_t → HsReq_t → Cookie → Salt_t → Tag_t →
                     'I_(2 ^ reply_nonce_bits) → HsWire_t).
  Context (open_req : ChanKeys_t → Hdr_t → Cookie → ReqSealed_t → option Payload_t).
  Context (answer : Theta_t → Msg_t → HSeed_t → Hdr_t → Payload_t → option Answer_t).
  Context (seal_ans : ChanKeys_t → Hdr_t → Answer_t → 'I_(2 ^ reply_nonce_bits) → AnsWire_t).

  Definition no_key : AuthKey := zero_of_bits auth_bits.

  Definition hs_plain (req : HsReq_t) (msg : Msg_t) (salt : Salt_t) (k_auth : AuthKey)
    : CookiePlain_t :=
    ((fo_derive req.1 msg salt).2, (msg, (req.2.1, k_auth))).

  Definition hs_reply (ch : ChanKeys_t) (req : HsReq_t) (cookie : Cookie) (salt : Salt_t)
    (k_trans : TransKey_t) (rn : 'I_(2 ^ reply_nonce_bits)) : HsWire_t :=
    seal_hs ch req cookie salt (confirm k_trans req salt) rn.

  Definition serve (ch : ChanKeys_t) (theta : Theta_t) (msg : Msg_t) (hs : HSeed_t)
    (rq : Req_t) (rn : 'I_(2 ^ reply_nonce_bits)) : option AnsWire_t :=
    let '(hdr, (cookie, x)) := rq in
    obind (λ p, omap (λ a, seal_ans ch hdr a rn) (answer theta msg hs hdr p))
      (open_req ch hdr cookie x).

  Definition serve_plain (rq : Req_t) (rn : 'I_(2 ^ reply_nonce_bits)) (pt : CookiePlain_t)
    : option AnsWire_t :=
    serve (chan_keys pt.2.2.2) pt.1 pt.2.1 pt.2.2.1 rq rn.

  Definition resolve (K : seq AuthKey) (ref : AuthRef_t) : AuthKey :=
    match ref.1 with
    | Some i => nth no_key K i
    | None => ref.2
    end.

  Definition resolve_plain (K : seq AuthKey) (sp : SidePlain_t) : CookiePlain_t :=
    (sp.1, (sp.2.1, (sp.2.2.1, resolve K sp.2.2.2))).

  Definition exported (replace : bool) (fresh real : SessionKey_t) : SessionKey_t :=
    if replace then fresh else real.

  Definition untestable (T : chMap 'nat 'unit) (K : seq AuthKey) (i : nat) : bool :=
    (i \in domm T) || (size K <= i)%N.

  Definition kmap_loc : Location := mkloc 61 ([::] : chList AuthKey).
  Definition tested_loc : Location := mkloc 62 (emptym : chMap 'nat 'unit).
  Definition dmap_loc : Location := mkloc 69 (emptym : chMap McCt_t 'nat).
  Definition side_loc : Location := mkloc 70 (emptym : chMap Cookie SidePlain_t).
  Definition ttab_loc : Location := mkloc 71 (emptym : chMap EvalIn_t TransKey_t).
  Definition ctab_loc : Location := mkloc 72 (emptym : chMap 'nat ChanKeys_t).

  #[local] Notation seed_loc := (mlkem_seed_loc mlkem_key_bits).
  #[local] Notation ckey_loc := (key_loc cookie_key_bits).
  #[local] Notation cchal_loc := (chal_loc auth_bits McCt_t).
  #[local] Notation cissued_loc := (issued_loc cookie_bits CookiePlain_t).

  Definition TARGET : ident := 80%N.
  Definition HANDSHAKE_A : ident := 81%N.
  Definition REQUEST_A : ident := 82%N.
  Definition TEST : ident := 83%N.
  Definition COOKIE_RAND : ident := 84%N.
  Definition NEW_INST : ident := 85%N.
  Definition EVAL_T : ident := 86%N.
  Definition CHAN : ident := 87%N.
  Definition SESSION_KEY : ident := 88%N.

  Definition I_active : Interface :=
    [interface
      #val #[ TARGET ] : 'unit → 'ch(TargetOut_t) ;
      #val #[ HANDSHAKE_A ] : 'ch(HsReq_t) → 'ch(HsWire_t) ;
      #val #[ REQUEST_A ] : 'ch(Req_t) → 'ch(chOption AnsWire_t) ;
      #val #[ TEST ] : 'ch(TestIn_t) → 'ch(chOption SessionKey_t) ].

  Definition I_rand : Interface :=
    [interface #val #[ COOKIE_RAND ] : 'ch(CookiePlain_t) → 'ch(Cookie) ].

  Definition I_prf : Interface :=
    [interface
      #val #[ NEW_INST ] : 'unit → 'nat ;
      #val #[ EVAL_T ] : 'ch(EvalIn_t) → 'ch(TransKey_t) ;
      #val #[ CHAN ] : 'nat → 'ch(ChanKeys_t) ;
      #val #[ SESSION_KEY ] : 'ch(TestIn_t) → 'ch(chOption SessionKey_t) ].

  #[local] Notation I_cca_a := (I_cca auth_bits McPK_t McCt_t).
  #[local] Notation I_aead_a := (I_aead cookie_bits CookiePlain_t).
  #[local] Notation Challenge := (Challenge_t auth_bits McPK_t McCt_t).

  Definition Active (replace : bool) : package emptym I_active :=
    [package [fmap seed_loc ; ckey_loc ; kmap_loc ; tested_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut_t) {
        ms ← get seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        let ck := mlkem_encaps (mlkem_pk sd) r in
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K ck.2 ;;
        ret (mlkem_pk sd, (ck.1, (chan_keys ck.2, size K)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq_t)) : 'ch(HsWire_t) {
        ms ← get seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put seed_loc := Some s ;;
                        ret s
              end) ;;
        let k_auth := mlkem_decaps sd req.2.2 in
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req_t)) : 'ch(chOption AnsWire_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) (open_cookie ck rq.2.1))
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      }
    ].

  Definition R_cca (replace : bool) : package I_cca_a I_active :=
    [package [fmap ckey_loc ; kmap_loc ; tested_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut_t) {
        #import {sig #[ CHALLENGE ] : 'unit → 'ch(Challenge)} as challenge ;;
        x ← challenge Datatypes.tt ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K x.2.2 ;;
        ret (x.1, (x.2.1, (chan_keys x.2.2, size K)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq_t)) : 'ch(HsWire_t) {
        #import {sig #[ DECAPS ] : 'ch(McCt_t) → 'ch(AuthKey)} as decaps ;;
        k_auth ← decaps req.2.2 ;;
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req_t)) : 'ch(chOption AnsWire_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) (open_cookie ck rq.2.1))
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      }
    ].

  Definition R_int (replace : bool) : package I_aead_a I_active :=
    [package [fmap seed_loc ; cchal_loc ; kmap_loc ; tested_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut_t) {
        ms ← get seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        k' ← sample uniform (2 ^ auth_bits) ;;
        let c := (mlkem_encaps (mlkem_pk sd) r).1 in
        C ← get cchal_loc ;;
        #put cchal_loc := setm C c k' ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K k' ;;
        ret (mlkem_pk sd, (c, (chan_keys k', size K)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq_t)) : 'ch(HsWire_t) {
        #import {sig #[ ISSUE_COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie)} as issue ;;
        C ← get cchal_loc ;;
        k_auth ← (match C req.2.2 with
                  | Some k => ret k
                  | None =>
                      ms ← get seed_loc ;;
                      sd ← (match ms with
                            | Some s => ret s
                            | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                      #put seed_loc := Some s ;;
                                      ret s
                            end) ;;
                      ret (mlkem_decaps sd req.2.2)
                  end) ;;
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        cookie ← issue (hs_plain req msg salt k_auth) ;;
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req_t)) : 'ch(chOption AnsWire_t) {
        #import {sig #[ OPEN_COOKIE ] : 'ch(Cookie) → 'ch(chOption CookiePlain_t)} as open ;;
        r ← open rq.2.1 ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) r)
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      }
    ].

  Definition CookieRandReal : package emptym I_rand :=
    [package [fmap ckey_loc] ;
      #def #[ COOKIE_RAND ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        ret (seal_cookie ck pt n)
      }
    ].

  Definition CookieRandIdeal : package emptym I_rand :=
    [package emptym ;
      #def #[ COOKIE_RAND ] (_ : 'ch(CookiePlain_t)) : 'ch(Cookie) {
        c ← sample uniform (2 ^ cookie_bits) ;;
        ret c
      }
    ].

  Definition R_ind (replace : bool) : package I_rand I_active :=
    [package [fmap seed_loc ; cchal_loc ; kmap_loc ; tested_loc ; cissued_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut_t) {
        ms ← get seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        k' ← sample uniform (2 ^ auth_bits) ;;
        let c := (mlkem_encaps (mlkem_pk sd) r).1 in
        C ← get cchal_loc ;;
        #put cchal_loc := setm C c k' ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K k' ;;
        ret (mlkem_pk sd, (c, (chan_keys k', size K)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq_t)) : 'ch(HsWire_t) {
        #import {sig #[ COOKIE_RAND ] : 'ch(CookiePlain_t) → 'ch(Cookie)} as seal ;;
        C ← get cchal_loc ;;
        k_auth ← (match C req.2.2 with
                  | Some k => ret k
                  | None =>
                      ms ← get seed_loc ;;
                      sd ← (match ms with
                            | Some s => ret s
                            | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                      #put seed_loc := Some s ;;
                                      ret s
                            end) ;;
                      ret (mlkem_decaps sd req.2.2)
                  end) ;;
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        cookie ← seal (hs_plain req msg salt k_auth) ;;
        T ← get cissued_loc ;;
        #put cissued_loc := setm T cookie (hs_plain req msg salt k_auth) ;;
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req_t)) : 'ch(chOption AnsWire_t) {
        T ← get cissued_loc ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) (T rq.2.1))
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      }
    ].

  Definition PrfReal : package emptym I_prf :=
    [package [fmap kmap_loc ; tested_loc] ;
      #def #[ NEW_INST ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ auth_bits) ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ EVAL_T ] (q : 'ch(EvalIn_t)) : 'ch(TransKey_t) {
        K ← get kmap_loc ;;
        ret (kdf q.2 (nth no_key K q.1)).2
      } ;
      #def #[ CHAN ] (i : 'nat) : 'ch(ChanKeys_t) {
        K ← get kmap_loc ;;
        ret (chan_keys (nth no_key K i))
      } ;
      #def #[ SESSION_KEY ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        ret (Some (kdf ti.2 (nth no_key K ti.1)).1)
      }
    ].

  Definition PrfIdeal : package emptym I_prf :=
    [package [fmap kmap_loc ; tested_loc ; ttab_loc ; ctab_loc] ;
      #def #[ NEW_INST ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ auth_bits) ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ EVAL_T ] (q : 'ch(EvalIn_t)) : 'ch(TransKey_t) {
        K ← get kmap_loc ;;
        if (q.1 < size K)%N then
          TT ← get ttab_loc ;;
          match TT q with
          | Some kt => ret kt
          | None =>
              kt ← sample uniform (2 ^ transcript_bits) ;;
              #put ttab_loc := setm TT q kt ;;
              ret kt
          end
        else ret (kdf q.2 no_key).2
      } ;
      #def #[ CHAN ] (i : 'nat) : 'ch(ChanKeys_t) {
        K ← get kmap_loc ;;
        if (i < size K)%N then
          CT ← get ctab_loc ;;
          match CT i with
          | Some ch => ret ch
          | None =>
              ch ← sample uniform (2 ^ chan_bits) ;;
              #put ctab_loc := setm CT i ch ;;
              ret ch
          end
        else ret (chan_keys no_key)
      } ;
      #def #[ SESSION_KEY ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        ks ← sample uniform (2 ^ session_bits) ;;
        ret (Some ks)
      }
    ].

  Definition R_prf (replace : bool) : package I_prf I_active :=
    [package [fmap seed_loc ; dmap_loc ; side_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut_t) {
        #import {sig #[ NEW_INST ] : 'unit → 'nat} as new_inst ;;
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys_t)} as chan ;;
        ms ← get seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        let c := (mlkem_encaps (mlkem_pk sd) r).1 in
        i ← new_inst Datatypes.tt ;;
        D ← get dmap_loc ;;
        #put dmap_loc := setm D c i ;;
        ch ← chan i ;;
        ret (mlkem_pk sd, (c, (ch, i)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq_t)) : 'ch(HsWire_t) {
        #import {sig #[ EVAL_T ] : 'ch(EvalIn_t) → 'ch(TransKey_t)} as eval_t ;;
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys_t)} as chan ;;
        D ← get dmap_loc ;;
        ref ← (match D req.2.2 with
               | Some i => ret (Some i, no_key)
               | None =>
                   ms ← get seed_loc ;;
                   sd ← (match ms with
                         | Some s => ret s
                         | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                   #put seed_loc := Some s ;;
                                   ret s
                         end) ;;
                   ret (None, mlkem_decaps sd req.2.2)
               end) ;;
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        cookie ← sample uniform (2 ^ cookie_bits) ;;
        let K := (fo_derive req.1 msg salt).1 in
        keys ← (match ref.1 with
                | Some i =>
                    kt ← eval_t (i, K) ;;
                    ch ← chan i ;;
                    ret (kt, ch)
                | None => ret ((kdf K ref.2).2, chan_keys ref.2)
                end) ;;
        Sd ← get side_loc ;;
        #put side_loc := setm Sd cookie
          ((fo_derive req.1 msg salt).2, (msg, (req.2.1, ref))) ;;
        ret (hs_reply keys.2 req cookie salt keys.1 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req_t)) : 'ch(chOption AnsWire_t) {
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys_t)} as chan ;;
        Sd ← get side_loc ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        match Sd rq.2.1 with
        | None => ret None
        | Some sp =>
            ch ← (match sp.2.2.2.1 with
                  | Some i => chan i
                  | None => ret (chan_keys sp.2.2.2.2)
                  end) ;;
            ret (serve ch sp.1 sp.2.1 sp.2.2.1 rq rn)
        end
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn_t)) : 'ch(chOption SessionKey_t) {
        #import {sig #[ SESSION_KEY ] : 'ch(TestIn_t) → 'ch(chOption SessionKey_t)} as session_key ;;
        r ← session_key ti ;;
        match r with
        | None => ret None
        | Some ks =>
            fresh ← sample uniform (2 ^ session_bits) ;;
            ret (Some (exported replace fresh ks))
        end
      }
    ].

  Ltac sync_step :=
    ssprove_code_simpl; try (progress cbv zeta);
    first
      [ match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            case: mk => [?|] /=
        end
      | ssprove_sync_eq => ?
      | ssprove_sync_eq ].

  Ltac close_same :=
    eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].

  #[local] Notation CcaReal_a :=
    (CcaReal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation CcaIdeal_a :=
    (CcaIdeal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation AeadReal :=
    (CookieAeadReal cookie_key_bits cookie_nonce_bits cookie_bits CookiePlain_t seal_cookie open_cookie).
  #[local] Notation AeadIdeal :=
    (CookieAeadIdeal cookie_key_bits cookie_nonce_bits cookie_bits CookiePlain_t seal_cookie).


  Lemma active_is_cca_reduction b : Active b ≈₀ (R_cca b ∘ CcaReal_a)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma ideal_cca_is_int_reduction b : (R_cca b ∘ CcaIdeal_a)%pack ≈₀ (R_int b ∘ AeadReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma ideal_int_is_ind_reduction b : (R_int b ∘ AeadIdeal)%pack ≈₀ (R_ind b ∘ CookieRandReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma replaced_session_key_is_uniform :
    (R_prf false ∘ PrfIdeal)%pack ≈₀ (R_prf true ∘ PrfIdeal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    4: { ssprove_code_simpl.
         ssprove_sync_eq => T. ssprove_sync_eq => K.
         case: (untestable T K x.1) => /=.
         - by apply: r_ret.
         - ssprove_sync_eq.
           ssprove_swap_lhs 0%N.
           ssprove_sync_eq => ?. ssprove_sync_eq => ?.
           apply: r_ret => s0 s1 ->. by split. }
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma nth_rcons_old (K : seq AuthKey) k i : (i < size K)%N → nth no_key (rcons K k) i = nth no_key K i.
  Proof. move=> Hi; by rewrite nth_rcons Hi. Qed.

  Lemma nth_rcons_new (K : seq AuthKey) k : nth no_key (rcons K k) (size K) = k.
  Proof. by rewrite nth_rcons ltnn eqxx. Qed.

  Definition chal_dmap_agree (C : chMap McCt_t AuthKey) (D : chMap McCt_t 'nat) : Prop :=
    ∀ c, isSome (C c) = isSome (D c).

  Definition chal_dmap_keys (C : chMap McCt_t AuthKey) (D : chMap McCt_t 'nat) (K : seq AuthKey)
    : Prop :=
    ∀ c i, D c = Some i → (i < size K)%N ∧ C c = Some (nth no_key K i).

  Definition issued_side_agree (T : chMap Cookie CookiePlain_t) (Sd : chMap Cookie SidePlain_t)
    : Prop :=
    ∀ ck, match Sd ck with
          | None => T ck = None
          | Some sp =>
              match sp.2.2.2.1 with
              | None => T ck = Some (resolve_plain [::] sp)
              | Some _ => True
              end
          end.

  Definition issued_side_keys (T : chMap Cookie CookiePlain_t) (Sd : chMap Cookie SidePlain_t)
    (K : seq AuthKey) : Prop :=
    ∀ ck sp i, Sd ck = Some sp → sp.2.2.2.1 = Some i →
      (i < size K)%N ∧ T ck = Some (resolve_plain K sp).

  Lemma resolve_plain_rcons K k sp i :
    sp.2.2.2.1 = Some i → (i < size K)%N →
    resolve_plain (rcons K k) sp = resolve_plain K sp.
  Proof. by move=> E Hi; rewrite /resolve_plain /resolve E nth_rcons_old. Qed.

  Lemma chal_dmap_agree_set C D c k i :
    chal_dmap_agree C D → chal_dmap_agree (setm C c k) (setm D c i).
  Proof. move=> H c'; rewrite !setmE; case: eqP => // _; exact: H. Qed.

  Lemma chal_dmap_keys_target C D K c k :
    chal_dmap_keys C D K →
    chal_dmap_keys (setm C c k) (setm D c (size K)) (rcons K k).
  Proof.
    move=> H c' i; rewrite !setmE size_rcons; case: eqP => _ /=.
    - move=> [<-]; by rewrite ltnSn nth_rcons_new.
    - move=> /H [Hi ->]; by rewrite ltnW // nth_rcons_old.
  Qed.

  Lemma issued_side_keys_target T Sd K k :
    issued_side_keys T Sd K → issued_side_keys T Sd (rcons K k).
  Proof.
    move=> H ck sp i E Ei; case: (H _ _ _ E Ei) => Hi ->.
    by rewrite size_rcons ltnW // (resolve_plain_rcons _ _ _ _ Ei Hi).
  Qed.

  Lemma issued_side_agree_set T Sd ck pt sp :
    issued_side_agree T Sd →
    (sp.2.2.2.1 = None → pt = resolve_plain [::] sp) →
    issued_side_agree (setm T ck pt) (setm Sd ck sp).
  Proof.
    move=> H Hpt ck'; rewrite !setmE; case: eqP => _; last exact: H.
    case E: sp.2.2.2.1 => [i|] //=; by rewrite Hpt.
  Qed.

  Lemma issued_side_keys_set T Sd K ck pt sp :
    issued_side_keys T Sd K →
    (∀ i, sp.2.2.2.1 = Some i → (i < size K)%N ∧ pt = resolve_plain K sp) →
    issued_side_keys (setm T ck pt) (setm Sd ck sp) K.
  Proof.
    move=> H Hpt ck' sp' i; rewrite !setmE; case: eqP => _; last exact: H.
    move=> [<-] Ei; case: (Hpt _ Ei) => Hi ->; by split.
  Qed.

  Notation repr_inv :=
    (heap_ignore [fmap cchal_loc ; cissued_loc ; dmap_loc ; side_loc] ⋊
     rel_app [:: (lhs, cchal_loc) ; (rhs, dmap_loc)] chal_dmap_agree ⋊
     rel_app [:: (lhs, cchal_loc) ; (rhs, dmap_loc) ; (rhs, kmap_loc)] chal_dmap_keys ⋊
     rel_app [:: (lhs, cissued_loc) ; (rhs, side_loc)] issued_side_agree ⋊
     rel_app [:: (lhs, cissued_loc) ; (rhs, side_loc) ; (rhs, kmap_loc)] issued_side_keys).

  Ltac close_side :=
    first
      [ let H := fresh "H" in
        move=> H; apply: (issued_side_agree_set _ _ _ _ _ H) => /=;
        first [ intros; discriminate | reflexivity ]
      | let H := fresh "H" in
        move=> H; apply: (issued_side_keys_set _ _ _ _ _ _ H) => /=;
        first [ intros; discriminate | move=> ? [<-]; by split ] ].

  Lemma ideal_ind_is_prf_reduction b :
    (R_ind b ∘ CookieRandIdeal)%pack ≈₀ (R_prf b ∘ PrfReal)%pack.
  Proof.
    eapply eq_rel_perf_ind with repr_inv.
    { ssprove_invariant => //. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: try (progress cbv zeta).
    all: ssprove_code_simpl.
    - get_both ms.
      case: ms => [s|] /=.
      + ssprove_forget_all.
        ssprove_sync => r. ssprove_sync => k.
        apply: r_get_remember_lhs => C.
        ssprove_swap_lhs 0%N.
        get_both K.
        ssprove_swap_rhs 0%N.
        apply: r_get_remember_rhs => D.
        ssprove_swap_rhs 1%N.
        ssprove_contract_put_get_rhs.
        apply: r_put_lhs.
        apply: r_put_vs_put.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: try first [ exact: chal_dmap_agree_set | exact: chal_dmap_keys_target
                         | exact: issued_side_keys_target ].
        * apply: r_ret => s0 s1 Hinv /=; by rewrite nth_rcons_new.
      + ssprove_forget_all.
        ssprove_sync => s. ssprove_sync. 1: ssprove_invariant.
        ssprove_sync => r. ssprove_sync => k.
        apply: r_get_remember_lhs => C.
        ssprove_swap_lhs 0%N.
        get_both K.
        ssprove_swap_rhs 0%N.
        apply: r_get_remember_rhs => D.
        ssprove_swap_rhs 1%N.
        ssprove_contract_put_get_rhs.
        apply: r_put_lhs.
        apply: r_put_vs_put.
        apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: try first [ exact: chal_dmap_agree_set | exact: chal_dmap_keys_target
                         | exact: issued_side_keys_target ].
        * apply: r_ret => s0 s1 Hinv /=; by rewrite nth_rcons_new.
    - apply: r_get_remember_lhs => C.
      apply: r_get_remember_rhs => D.
      cbv zeta.
      ssprove_rem_rel 3%N => HA1.
      have Hag := HA1 x.2.2.
      case HC: (C x.2.2) => [k|]; case HD: (D x.2.2) => [i|] /=; rewrite HC HD /= in Hag;
        try discriminate.
      + ssprove_sync => msg. ssprove_sync => salt. ssprove_sync => rn. ssprove_sync => ck.
        apply: r_get_remember_lhs => T.
        ssprove_contract_get_rhs.
        apply: r_get_remember_rhs => K.
        apply: r_get_remember_rhs => Sd.
        ssprove_rem_rel 2%N => HA2.
        case: (HA2 _ _ HD) => Hi; rewrite HC => -[Hk]. subst k.
        apply: r_put_lhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: close_side.
        * apply: r_ret => s0 s1 Hinv; by split.
      + get_both ms.
        case: ms => [s|] /=.
        * ssprove_sync => msg. ssprove_sync => salt. ssprove_sync => rn. ssprove_sync => ck.
          apply: r_get_remember_lhs => T.
          apply: r_get_remember_rhs => Sd.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             all: close_side.
          -- apply: r_ret => s0 s1 Hinv; by split.
        * do 2 ssprove_forget.
          ssprove_sync => s. ssprove_sync. 1: ssprove_invariant.
          ssprove_sync => msg. ssprove_sync => salt. ssprove_sync => rn. ssprove_sync => ck.
          apply: r_get_remember_lhs => T.
          apply: r_get_remember_rhs => Sd.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             all: close_side.
          -- apply: r_ret => s0 s1 Hinv; by split.
    - apply: r_get_remember_lhs => T.
      apply: r_get_remember_rhs => Sd.
      ssprove_rem_rel 1%N => HB1.
      ssprove_sync => rn.
      cbv beta zeta.
      have HB := HB1 x.2.1.
      case HS: (Sd x.2.1) => [sp|]; rewrite HS in HB.
      + case Hr: sp.2.2.2.1 => [i|]; rewrite Hr in HB.
        * apply: r_get_remember_rhs => K.
          ssprove_rem_rel 0%N => HB2.
          case: (HB2 _ _ _ HS Hr) => _ HT.
          rewrite HT /=.
          ssprove_forget_all.
          apply: r_ret => s0 s1 Hinv; split => //.
          by rewrite /serve_plain /resolve_plain /= /resolve Hr.
        * rewrite HB /=.
          ssprove_forget_all.
          apply: r_ret => s0 s1 Hinv; split => //.
          by rewrite /serve_plain /resolve_plain /= /resolve Hr.
      + rewrite HB /=.
        ssprove_forget_all.
        by apply: r_ret.
    - get_both T. get_both K.
      case: (untestable T K x.1) => /=.
      + ssprove_forget_all. by apply: r_ret.
      + ssprove_forget_all.
        ssprove_sync. 1: ssprove_invariant.
        ssprove_sync => fresh.
        apply: r_ret => s0 s1 Hinv; by split.
  Qed.

  Definition active_locs : Locations :=
    [fmap seed_loc ; ckey_loc ; kmap_loc ; tested_loc ; cchal_loc ; cissued_loc ;
          dmap_loc ; side_loc ; ttab_loc ; ctab_loc].

  Lemma fsep_sub (LA N M : Locations) : fseparate LA M → fsubmap N M → fseparate LA N.
  Proof.
    move=> [H] Hs; constructor; move: H; rewrite -Hs domm_union fdisjointUr.
    by case/andP.
  Qed.

  Ltac solve_active_sep :=
    lazymatch goal with
    | H : fseparate ?LA active_locs |- fseparate ?LA _ =>
        apply: (fsep_sub _ _ _ H); fmap_solve
    end.

  Theorem active_hops b :
    ∀ LA A,
      ValidPackage LA I_active A_export A →
      fseparate LA active_locs →
      AdvantageE (Active b) (R_prf b ∘ PrfIdeal)%pack A
      <= AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_cca b)%pack
         + AdvantageE AeadReal AeadIdeal (A ∘ R_int b)%pack
         + AdvantageE CookieRandReal CookieRandIdeal (A ∘ R_ind b)%pack
         + AdvantageE PrfReal PrfIdeal (A ∘ R_prf b)%pack.
  Proof.
    move=> LA A VA Hsep.
    ssprove triangle (Active b) [::
      (R_cca b ∘ CcaReal_a)%pack ;
      (R_cca b ∘ CcaIdeal_a)%pack ;
      (R_int b ∘ AeadReal)%pack ;
      (R_int b ∘ AeadIdeal)%pack ;
      (R_ind b ∘ CookieRandReal)%pack ;
      (R_ind b ∘ CookieRandIdeal)%pack ;
      (R_prf b ∘ PrfReal)%pack
    ] (R_prf b ∘ PrfIdeal)%pack A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE (Active b) (R_cca b ∘ CcaReal_a)%pack A = 0.
    { apply: active_is_cca_reduction; solve_active_sep. }
    have Z2 : AdvantageE (R_cca b ∘ CcaIdeal_a)%pack (R_int b ∘ AeadReal)%pack A = 0.
    { apply: ideal_cca_is_int_reduction; solve_active_sep. }
    have Z3 : AdvantageE (R_int b ∘ AeadIdeal)%pack (R_ind b ∘ CookieRandReal)%pack A = 0.
    { apply: ideal_int_is_ind_reduction; solve_active_sep. }
    have Z4 : AdvantageE (R_ind b ∘ CookieRandIdeal)%pack (R_prf b ∘ PrfReal)%pack A = 0.
    { apply: ideal_ind_is_prf_reduction; solve_active_sep. }
    rewrite Z1 Z2 Z3 Z4 GRing.add0r !GRing.addr0.
    by rewrite !Advantage_link.
  Qed.

  Theorem active_session_key_secrecy :
    ∀ LA A,
      ValidPackage LA I_active A_export A →
      fseparate LA active_locs →
      AdvantageE (Active false) (Active true) A
      <= (AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_cca false)%pack
          + AdvantageE AeadReal AeadIdeal (A ∘ R_int false)%pack
          + AdvantageE CookieRandReal CookieRandIdeal (A ∘ R_ind false)%pack
          + AdvantageE PrfReal PrfIdeal (A ∘ R_prf false)%pack)
         + (AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_cca true)%pack
            + AdvantageE AeadReal AeadIdeal (A ∘ R_int true)%pack
            + AdvantageE CookieRandReal CookieRandIdeal (A ∘ R_ind true)%pack
            + AdvantageE PrfReal PrfIdeal (A ∘ R_prf true)%pack).
  Proof.
    move=> LA A VA Hsep.
    ssprove triangle (Active false) [::
      (R_prf false ∘ PrfIdeal)%pack ;
      (R_prf true ∘ PrfIdeal)%pack
    ] (Active true) A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z : AdvantageE (R_prf false ∘ PrfIdeal)%pack (R_prf true ∘ PrfIdeal)%pack A = 0.
    { apply: replaced_session_key_is_uniform; solve_active_sep. }
    rewrite Z GRing.addr0 [AdvantageE _ (Active true) _]Advantage_sym.
    apply: Num.Theory.lerD.
    - exact: active_hops VA Hsep.
    - exact: active_hops VA Hsep.
  Qed.

  #[local] Notation CcaStdReal_a :=
    (CcaStdReal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation CcaStdIdeal_a :=
    (CcaStdIdeal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation R_std_a := (R_std auth_bits McPK_t McCt_t).

  Context (mlkem_correct : ∀ s r,
    mlkem_decaps s (mlkem_encaps (mlkem_pk s) r).1 = (mlkem_encaps (mlkem_pk s) r).2).

  Lemma cca_term_std b LA A :
    ValidPackage LA I_active A_export A →
    fseparate LA active_locs →
    fseparate LA [fmap refuse_loc McCt_t] →
    AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_cca b)%pack
    <= AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_cca b) ∘ R_std_a)%pack.
  Proof.
    move=> VA Hsep Href.
    unshelve eapply (cca_from_standard _ _ _ _ _ _ _ _ mlkem_correct _ _).
    1: exact (unionm LA [fmap ckey_loc ; kmap_loc ; tested_loc]).
    1: ssprove_valid.
    - apply: fseparate_compat; rewrite /=; solve_active_sep.
    - apply: fseparateUl; first solve_active_sep. fmap_solve.
    - apply: fseparateUl; first solve_active_sep. fmap_solve.
    - apply: fseparateUl; first done. fmap_solve.
  Qed.

  Theorem active_session_key_secrecy_std :
    ∀ LA A,
      ValidPackage LA I_active A_export A →
      fseparate LA active_locs →
      fseparate LA [fmap refuse_loc McCt_t] →
      AdvantageE (Active false) (Active true) A
      <= (AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_cca false) ∘ R_std_a)%pack
          + AdvantageE AeadReal AeadIdeal (A ∘ R_int false)%pack
          + AdvantageE CookieRandReal CookieRandIdeal (A ∘ R_ind false)%pack
          + AdvantageE PrfReal PrfIdeal (A ∘ R_prf false)%pack)
         + (AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_cca true) ∘ R_std_a)%pack
            + AdvantageE AeadReal AeadIdeal (A ∘ R_int true)%pack
            + AdvantageE CookieRandReal CookieRandIdeal (A ∘ R_ind true)%pack
            + AdvantageE PrfReal PrfIdeal (A ∘ R_prf true)%pack).
  Proof.
    move=> LA A VA Hsep Href.
    eapply Order.POrderTheory.le_trans; first exact: active_session_key_secrecy VA Hsep.
    apply: Num.Theory.lerD; do 3 (apply: Num.Theory.lerD => //);
      exact: cca_term_std.
  Qed.

End ActiveSecrecy.
