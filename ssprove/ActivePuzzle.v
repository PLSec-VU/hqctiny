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

From SSProveHQC Require Import CookieIntegrity MLKEMCCA PuzzleKeys ActiveSecrecy.

Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
Notation " 'ch ( x ) " := x (at level 2) : package_scope.

Lemma r_set_both_weaken {A B : choiceType} (ℓ : Location) (v : ℓ) (P Q : precond)
  (c₀ : raw_code A) (c₁ : raw_code B) (post : postcond A B) :
  (∀ s₀ s₁, P (s₀, s₁) → Q (set_heap s₀ ℓ v, set_heap s₁ ℓ v)) →
  ⊢ ⦃ λ '(s₀, s₁), Q (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄ →
  ⊢ ⦃ λ '(s₀, s₁), set_rhs ℓ v (set_lhs ℓ v P) (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄.
Proof.
  move=> HPQ H.
  eapply rpre_weaken_rule; first exact: H.
  move=> s₀ s₁ [s₁' [[s₀' [HP ->]] ->]].
  exact: HPQ.
Qed.

Lemma heap_ignore_set_both (L : Locations) (ℓ : Location) (v : ℓ) s₀ s₁ :
  heap_ignore L (s₀, s₁) → heap_ignore L (set_heap s₀ ℓ v, set_heap s₁ ℓ v).
Proof.
  move=> H ℓ₀ hℓ₀.
  case E: (ℓ₀.1 != ℓ.1).
  - rewrite !get_set_heap_neq //. exact: H.
  - move: E => /negbFE /eqP E.
    rewrite /get_heap !setmE E eqxx //.
Qed.

Section ActivePuzzle.

  Context (mlkem_key_bits mlkem_coin_bits auth_bits : nat).
  Context (McPK_t McCt_t : choice_type).
  Context (cookie_key_bits cookie_nonce_bits cookie_bits : nat).
  Context (msg_bits salt_bits reply_nonce_bits session_bits transcript_bits chan_bits : nat).
  Context (HEk_t HSeed_t Theta_t Key_t Tag_t : choice_type).
  Context (Hdr_t ReqSealed_t Payload_t Answer_t HsWire_t AnsWire_t : choice_type).
  Context (mac_key_bits coins_key_bits coins_bits : nat).
  Context (MacIn_t PuzzleTag_t PNonce_t Digest_t Work_t : choice_type).

  #[local] Notation AuthKey := (MlkemKey_t auth_bits).
  #[local] Notation MlkemSeed := (MlkemSeed_t mlkem_key_bits).
  #[local] Notation CookieKey := (CookieKey_t cookie_key_bits).
  #[local] Notation Cookie := (Cookie_t cookie_bits).
  #[local] Notation Msg := (Msg_t msg_bits).
  #[local] Notation Salt := (Salt_t salt_bits).
  #[local] Notation SessionKey := (SessionKey_t session_bits).
  #[local] Notation TransKey := (TransKey_t transcript_bits).
  #[local] Notation ChanKeys := (ChanKeys_t chan_bits).
  #[local] Notation CookiePlain := (CookiePlain_t auth_bits msg_bits HSeed_t Theta_t).
  #[local] Notation SidePlain := (SidePlain_t auth_bits msg_bits HSeed_t Theta_t).
  #[local] Notation HsReq := (HsReq_t McCt_t HEk_t HSeed_t).
  #[local] Notation Req := (Req_t cookie_bits Hdr_t ReqSealed_t).
  #[local] Notation TargetOut := (TargetOut_t McPK_t McCt_t chan_bits).
  #[local] Notation TestIn := (TestIn_t Key_t).
  #[local] Notation EvalIn := (EvalIn_t Key_t).
  #[local] Notation MacKey := (MacKey_t mac_key_bits).
  #[local] Notation CoinsKey := (CoinsKey_t coins_key_bits).
  #[local] Notation Coins := (Coins_t coins_bits).

  Definition CNonce_t := chFin (2 ^ cookie_nonce_bits).
  Definition Split_t := chProd Msg (chProd Salt CNonce_t).
  Definition CoinsIn_t := chProd PNonce_t Digest_t.
  Definition Label_t := chProd PNonce_t HsReq.
  Definition Solved_t := chProd (chProd MacIn_t PuzzleTag_t) (chProd Work_t HsReq).
  Definition Cached_t := chProd Cookie (chProd Salt (chProd TransKey ChanKeys)).

  Context (mlkem_pk : MlkemSeed → McPK_t).
  Context (mlkem_encaps : McPK_t → 'I_(2 ^ mlkem_coin_bits) → McCt_t * AuthKey).
  Context (mlkem_decaps : MlkemSeed → McCt_t → AuthKey).
  Context (fo_derive : HEk_t → Msg → Salt → Key_t * Theta_t).
  Context (kdf : Key_t → AuthKey → SessionKey * TransKey).
  Context (chan_keys : AuthKey → ChanKeys).
  Context (confirm : TransKey → HsReq → Salt → Tag_t).
  Context (seal_cookie : CookieKey → CookiePlain → 'I_(2 ^ cookie_nonce_bits) → Cookie).
  Context (open_cookie : CookieKey → Cookie → option CookiePlain).
  Context (seal_hs : ChanKeys → HsReq → Cookie → Salt → Tag_t →
                     'I_(2 ^ reply_nonce_bits) → HsWire_t).
  Context (open_req : ChanKeys → Hdr_t → Cookie → ReqSealed_t → option Payload_t).
  Context (answer : Theta_t → Msg → HSeed_t → Hdr_t → Payload_t → option Answer_t).
  Context (seal_ans : ChanKeys → Hdr_t → Answer_t → 'I_(2 ^ reply_nonce_bits) → AnsWire_t).
  Context (mac_key_of : CookieKey → MacKey).
  Context (coins_key_of : CookieKey → CoinsKey).
  Context (puzzle_mac : MacKey → MacIn_t → PuzzleTag_t).
  Context (puzzle_coins : CoinsKey → CoinsIn_t → Coins).
  Context (split_coins : Coins → Split_t).
  Context (digest : HsReq → Digest_t).
  Context (chal_nonce : MacIn_t → PNonce_t).
  Context (work_ok : MacIn_t → Digest_t → Work_t → bool).

  #[local] Notation hs_plain :=
    (ActiveSecrecy.hs_plain auth_bits McCt_t msg_bits salt_bits HEk_t HSeed_t Theta_t Key_t
       fo_derive).
  #[local] Notation hs_reply :=
    (ActiveSecrecy.hs_reply McCt_t cookie_bits salt_bits reply_nonce_bits transcript_bits
       chan_bits HEk_t HSeed_t Tag_t HsWire_t confirm seal_hs).
  #[local] Notation serve :=
    (ActiveSecrecy.serve cookie_bits msg_bits reply_nonce_bits chan_bits HSeed_t Theta_t Hdr_t
       ReqSealed_t Payload_t Answer_t AnsWire_t open_req answer seal_ans).
  #[local] Notation serve_plain :=
    (ActiveSecrecy.serve_plain auth_bits cookie_bits msg_bits reply_nonce_bits chan_bits HSeed_t
       Theta_t Hdr_t ReqSealed_t Payload_t Answer_t AnsWire_t chan_keys open_req answer seal_ans).
  #[local] Notation resolve_plain := (ActiveSecrecy.resolve_plain auth_bits msg_bits HSeed_t Theta_t).
  #[local] Notation exported := (ActiveSecrecy.exported session_bits).
  #[local] Notation untestable := (ActiveSecrecy.untestable auth_bits).
  #[local] Notation no_key := (ActiveSecrecy.no_key auth_bits).

  #[local] Notation seed_loc := (mlkem_seed_loc mlkem_key_bits).
  #[local] Notation ckey_loc := (key_loc cookie_key_bits).
  #[local] Notation cchal_loc := (chal_loc auth_bits McCt_t).
  #[local] Notation cissued_loc := (issued_loc cookie_bits CookiePlain).
  #[local] Notation kmap_loc := (ActiveSecrecy.kmap_loc auth_bits).
  #[local] Notation dmap_loc := (ActiveSecrecy.dmap_loc McCt_t).
  #[local] Notation side_loc := (ActiveSecrecy.side_loc auth_bits cookie_bits msg_bits HSeed_t Theta_t).
  #[local] Notation ttab_loc := (ActiveSecrecy.ttab_loc transcript_bits Key_t).
  #[local] Notation ctab_loc := (ActiveSecrecy.ctab_loc chan_bits).
  #[local] Notation pmkey_loc := (mkey_loc mac_key_bits).
  #[local] Notation pckoins_loc := (ckoins_loc coins_key_bits).

  Definition cache_loc : Location := mkloc 110 (emptym : chMap Label_t Cached_t).
  Definition coins3_loc : Location := mkloc 111 (emptym : chMap CoinsIn_t Split_t).
  Definition hash_loc : Location := mkloc 112 (emptym : chMap Digest_t HsReq).

  Definition CHAL_P : ident := 120%N.
  Definition SOLVED_P : ident := 121%N.
  Definition PCOINS3 : ident := 122%N.
  Definition HASH : ident := 123%N.

  Definition puzzle_check (expected : PuzzleTag_t) (s : Solved_t) : bool :=
    (s.1.2 == expected) && work_ok s.1.1 (digest s.2.2) s.2.1.

  Definition label_of (s : Solved_t) : Label_t := (chal_nonce s.1.1, s.2.2).

  Definition coins_in (l : Label_t) : CoinsIn_t := (l.1, digest l.2).

  Definition reply_of (req : HsReq) (v : Cached_t) (rn : 'I_(2 ^ reply_nonce_bits)) : HsWire_t :=
    hs_reply v.2.2.2 req v.1 v.2.1 v.2.2.1 rn.

  Definition cached_of (req : HsReq) (k_auth : AuthKey) (sp : Split_t) (cookie : Cookie)
    : Cached_t :=
    (cookie, (sp.2.1, ((kdf (fo_derive req.1 sp.1 sp.2.1).1 k_auth).2, chan_keys k_auth))).

  Definition solve_val (ck_coins ck_seal : CookieKey) (sd : MlkemSeed) (l : Label_t) : Cached_t :=
    let k_auth := mlkem_decaps sd l.2.2.2 in
    let sp := split_coins (puzzle_coins (coins_key_of ck_coins) (coins_in l)) in
    cached_of l.2 k_auth sp (seal_cookie ck_seal (hs_plain l.2 sp.1 sp.2.1 k_auth) sp.2.2).

  Definition I_active_p : Interface :=
    [interface
      #val #[ TARGET ] : 'unit → 'ch(TargetOut) ;
      #val #[ HANDSHAKE_A ] : 'ch(HsReq) → 'ch(HsWire_t) ;
      #val #[ REQUEST_A ] : 'ch(Req) → 'ch(chOption AnsWire_t) ;
      #val #[ TEST ] : 'ch(TestIn) → 'ch(chOption SessionKey) ;
      #val #[ CHAL_P ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t) ;
      #val #[ SOLVED_P ] : 'ch(Solved_t) → 'ch(chOption HsWire_t) ].

  Definition I_coins3 : Interface :=
    [interface #val #[ PCOINS3 ] : 'ch(CoinsIn_t) → 'ch(Split_t) ].

  Definition I_cr : Interface :=
    [interface #val #[ HASH ] : 'ch(HsReq) → 'ch(chOption Digest_t) ].

  #[local] Notation I_keysep_a :=
    (I_keysep cookie_nonce_bits cookie_bits coins_bits CookiePlain MacIn_t PuzzleTag_t CoinsIn_t).
  #[local] Notation I_cca_a := (I_cca auth_bits McPK_t McCt_t).
  #[local] Notation I_aead_a := (I_aead cookie_bits CookiePlain).
  #[local] Notation I_rand_a := (I_rand auth_bits cookie_bits msg_bits HSeed_t Theta_t).
  #[local] Notation I_prf_a := (I_prf session_bits transcript_bits chan_bits Key_t).
  #[local] Notation Challenge := (Challenge_t auth_bits McPK_t McCt_t).


  Definition ActiveP (replace : bool) : package emptym I_active_p :=
    [package [fmap seed_loc ; ckey_loc ; kmap_loc ; tested_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
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
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
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
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac (mac_key_of ck) x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac (mac_key_of ck) s.1.1) s then
          ms ← get seed_loc ;;
          sd ← (match ms with
                | Some s => ret s
                | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                          #put seed_loc := Some s ;;
                          ret s
                end) ;;
          kk1 ← get ckey_loc ;;
          ck1 ← (match kk1 with
                 | Some k => ret k
                 | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                           #put ckey_loc := Some k ;;
                           ret k
                 end) ;;
          kk2 ← get ckey_loc ;;
          ck2 ← (match kk2 with
                 | Some k => ret k
                 | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                           #put ckey_loc := Some k ;;
                           ret k
                 end) ;;
          rn ← sample uniform (2 ^ reply_nonce_bits) ;;
          ret (Some (reply_of s.2.2 (solve_val ck1 ck2 sd (label_of s)) rn))
        else ret None
      }
    ].


  Definition R_ks (replace : bool) : package I_keysep_a I_active_p :=
    [package [fmap seed_loc ; kmap_loc ; tested_loc ; cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
        #import {sig #[ SEAL_N ] : 'ch(chProd CookiePlain ('fin (2 ^ cookie_nonce_bits)))
                                     → 'ch(Cookie)} as seal ;;
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
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        cookie ← seal (hs_plain req msg salt k_auth, n) ;;
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
        #import {sig #[ OPEN_C ] : 'ch(Cookie) → 'ch(chOption CookiePlain)} as open ;;
        r ← open rq.2.1 ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) r)
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        #import {sig #[ PMAC ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t)} as pmac ;;
        t ← pmac x ;;
        ret t
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ PMAC ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t)} as pmac ;;
        #import {sig #[ PCOINS ] : 'ch(CoinsIn_t) → 'ch(Coins)} as pcoins ;;
        #import {sig #[ SEAL_N ] : 'ch(chProd CookiePlain ('fin (2 ^ cookie_nonce_bits)))
                                     → 'ch(Cookie)} as seal ;;
        t ← pmac s.1.1 ;;
        if puzzle_check t s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              ms ← get seed_loc ;;
              sd ← (match ms with
                    | Some s => ret s
                    | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                              #put seed_loc := Some s ;;
                              ret s
                    end) ;;
              let k_auth := mlkem_decaps sd s.2.2.2.2 in
              cs ← pcoins (coins_in (label_of s)) ;;
              let sp := split_coins cs in
              cookie ← seal (hs_plain s.2.2 sp.1 sp.2.1 k_auth, sp.2.2) ;;
              let v := cached_of s.2.2 k_auth sp cookie in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].


  Definition CoinsSplitReal : package emptym I_coins3 :=
    [package [fmap pckoins_loc] ;
      #def #[ PCOINS3 ] (y : 'ch(CoinsIn_t)) : 'ch(Split_t) {
        cc ← get pckoins_loc ;;
        kc ← (match cc with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ coins_key_bits) ;;
                        #put pckoins_loc := Some k ;;
                        ret k
              end) ;;
        ret (split_coins (puzzle_coins kc y))
      }
    ].

  Definition CoinsSplitIdeal : package emptym I_coins3 :=
    [package [fmap coins3_loc] ;
      #def #[ PCOINS3 ] (y : 'ch(CoinsIn_t)) : 'ch(Split_t) {
        T ← get coins3_loc ;;
        match T y with
        | Some sp => ret sp
        | None =>
            m ← sample uniform (2 ^ msg_bits) ;;
            sa ← sample uniform (2 ^ salt_bits) ;;
            n ← sample uniform (2 ^ cookie_nonce_bits) ;;
            #put coins3_loc := setm T y (m, (sa, n)) ;;
            ret (m, (sa, n))
        end
      }
    ].


  Definition CrReal : package emptym I_cr :=
    [package emptym ;
      #def #[ HASH ] (x : 'ch(HsReq)) : 'ch(chOption Digest_t) {
        ret (Some (digest x))
      }
    ].

  Definition CrIdeal : package emptym I_cr :=
    [package [fmap hash_loc] ;
      #def #[ HASH ] (x : 'ch(HsReq)) : 'ch(chOption Digest_t) {
        H ← get hash_loc ;;
        match H (digest x) with
        | Some x' => ret (if x' == x then Some (digest x) else None)
        | None =>
            #put hash_loc := setm H (digest x) x ;;
            ret (Some (digest x))
        end
      }
    ].

  Definition R_co (replace : bool) : package I_coins3 I_active_p :=
    [package [fmap seed_loc ; ckey_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
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
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
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
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ PCOINS3 ] : 'ch(CoinsIn_t) → 'ch(Split_t)} as pcoins ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              ms ← get seed_loc ;;
              sd ← (match ms with
                    | Some s => ret s
                    | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                              #put seed_loc := Some s ;;
                              ret s
                    end) ;;
              let k_auth := mlkem_decaps sd s.2.2.2.2 in
              sp ← pcoins (coins_in (label_of s)) ;;
              kk ← get ckey_loc ;;
              ck ← (match kk with
                    | Some k => ret k
                    | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                              #put ckey_loc := Some k ;;
                              ret k
                    end) ;;
              let v := cached_of s.2.2 k_auth sp
                         (seal_cookie ck (hs_plain s.2.2 sp.1 sp.2.1 k_auth) sp.2.2) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  Definition R_cr (replace : bool) : package I_cr I_active_p :=
    [package [fmap seed_loc ; ckey_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cache_loc ;
               coins3_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
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
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
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
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ HASH ] : 'ch(HsReq) → 'ch(chOption Digest_t)} as hash ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              ms ← get seed_loc ;;
              sd ← (match ms with
                    | Some s => ret s
                    | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                              #put seed_loc := Some s ;;
                              ret s
                    end) ;;
              let k_auth := mlkem_decaps sd s.2.2.2.2 in
              od ← hash s.2.2 ;;
              sp ← (match od with
                    | Some d =>
                        T ← get coins3_loc ;;
                        match T (chal_nonce s.1.1, d) with
                        | Some sp => ret sp
                        | None =>
                            m ← sample uniform (2 ^ msg_bits) ;;
                            sa ← sample uniform (2 ^ salt_bits) ;;
                            n ← sample uniform (2 ^ cookie_nonce_bits) ;;
                            #put coins3_loc := setm T (chal_nonce s.1.1, d) (m, (sa, n)) ;;
                            ret (m, (sa, n))
                        end
                    | None =>
                        m ← sample uniform (2 ^ msg_bits) ;;
                        sa ← sample uniform (2 ^ salt_bits) ;;
                        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
                        ret (m, (sa, n))
                    end) ;;
              kk ← get ckey_loc ;;
              ck ← (match kk with
                    | Some k => ret k
                    | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                              #put ckey_loc := Some k ;;
                              ret k
                    end) ;;
              let v := cached_of s.2.2 k_auth sp
                         (seal_cookie ck (hs_plain s.2.2 sp.1 sp.2.1 k_auth) sp.2.2) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  Definition R_ccap (replace : bool) : package I_cca_a I_active_p :=
    [package [fmap ckey_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
        #import {sig #[ CHALLENGE ] : 'unit → 'ch(Challenge)} as challenge ;;
        x ← challenge Datatypes.tt ;;
        K ← get kmap_loc ;;
        #put kmap_loc := rcons K x.2.2 ;;
        ret (x.1, (x.2.1, (chan_keys x.2.2, size K)))
      } ;
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
        #import {sig #[ DECAPS ] : 'ch(McCt_t) → 'ch(AuthKey)} as decaps ;;
        k_auth ← decaps req.2.2 ;;
        msg ← sample uniform (2 ^ msg_bits) ;;
        salt ← sample uniform (2 ^ salt_bits) ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        let cookie := seal_cookie ck (hs_plain req msg salt k_auth) n in
        ret (hs_reply (chan_keys k_auth) req cookie salt
               (kdf (fo_derive req.1 msg salt).1 k_auth).2 rn)
      } ;
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
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
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ DECAPS ] : 'ch(McCt_t) → 'ch(AuthKey)} as decaps ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              k_auth ← decaps s.2.2.2.2 ;;
              m ← sample uniform (2 ^ msg_bits) ;;
              sa ← sample uniform (2 ^ salt_bits) ;;
              n ← sample uniform (2 ^ cookie_nonce_bits) ;;
              kk ← get ckey_loc ;;
              ck ← (match kk with
                    | Some k => ret k
                    | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                              #put ckey_loc := Some k ;;
                              ret k
                    end) ;;
              let v := cached_of s.2.2 k_auth (m, (sa, n))
                         (seal_cookie ck (hs_plain s.2.2 m sa k_auth) n) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  Definition R_intp (replace : bool) : package I_aead_a I_active_p :=
    [package [fmap seed_loc ; cchal_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
        #import {sig #[ ISSUE_COOKIE ] : 'ch(CookiePlain) → 'ch(Cookie)} as issue ;;
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
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
        #import {sig #[ OPEN_COOKIE ] : 'ch(Cookie) → 'ch(chOption CookiePlain)} as open ;;
        r ← open rq.2.1 ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) r)
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ ISSUE_COOKIE ] : 'ch(CookiePlain) → 'ch(Cookie)} as issue ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              C ← get cchal_loc ;;
              k_auth ← (match C s.2.2.2.2 with
                        | Some k => ret k
                        | None =>
                            ms ← get seed_loc ;;
                            sd ← (match ms with
                                  | Some s => ret s
                                  | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                            #put seed_loc := Some s ;;
                                            ret s
                                  end) ;;
                            ret (mlkem_decaps sd s.2.2.2.2)
                        end) ;;
              m ← sample uniform (2 ^ msg_bits) ;;
              sa ← sample uniform (2 ^ salt_bits) ;;
              cookie ← issue (hs_plain s.2.2 m sa k_auth) ;;
              let v := (cookie, (sa, ((kdf (fo_derive s.2.2.1 m sa).1 k_auth).2,
                                      chan_keys k_auth))) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  #[local] Notation COOKIE_RAND := ActiveSecrecy.COOKIE_RAND.

  Definition R_indp (replace : bool) : package I_rand_a I_active_p :=
    [package [fmap seed_loc ; cchal_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cissued_loc ;
               cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
        #import {sig #[ COOKIE_RAND ] : 'ch(CookiePlain) → 'ch(Cookie)} as seal ;;
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
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
        T ← get cissued_loc ;;
        rn ← sample uniform (2 ^ reply_nonce_bits) ;;
        ret (obind (serve_plain rq rn) (T rq.2.1))
      } ;
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        T ← get tested_loc ;;
        K ← get kmap_loc ;;
        if untestable T K ti.1 then ret None else
        #put tested_loc := setm T ti.1 Datatypes.tt ;;
        fresh ← sample uniform (2 ^ session_bits) ;;
        ret (Some (exported replace fresh (kdf ti.2 (nth no_key K ti.1)).1))
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ COOKIE_RAND ] : 'ch(CookiePlain) → 'ch(Cookie)} as seal ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              C ← get cchal_loc ;;
              k_auth ← (match C s.2.2.2.2 with
                        | Some k => ret k
                        | None =>
                            ms ← get seed_loc ;;
                            sd ← (match ms with
                                  | Some s => ret s
                                  | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                            #put seed_loc := Some s ;;
                                            ret s
                                  end) ;;
                            ret (mlkem_decaps sd s.2.2.2.2)
                        end) ;;
              m ← sample uniform (2 ^ msg_bits) ;;
              sa ← sample uniform (2 ^ salt_bits) ;;
              cookie ← seal (hs_plain s.2.2 m sa k_auth) ;;
              T ← get cissued_loc ;;
              #put cissued_loc := setm T cookie (hs_plain s.2.2 m sa k_auth) ;;
              let v := (cookie, (sa, ((kdf (fo_derive s.2.2.1 m sa).1 k_auth).2,
                                      chan_keys k_auth))) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  #[local] Notation NEW_INST := ActiveSecrecy.NEW_INST.
  #[local] Notation EVAL_T := ActiveSecrecy.EVAL_T.
  #[local] Notation CHAN := ActiveSecrecy.CHAN.
  #[local] Notation SESSION_KEY := ActiveSecrecy.SESSION_KEY.

  Definition R_prfp (replace : bool) : package I_prf_a I_active_p :=
    [package [fmap seed_loc ; dmap_loc ; side_loc ; pmkey_loc ; cache_loc] ;
      #def #[ TARGET ] (_ : 'unit) : 'ch(TargetOut) {
        #import {sig #[ NEW_INST ] : 'unit → 'nat} as new_inst ;;
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys)} as chan ;;
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
      #def #[ HANDSHAKE_A ] (req : 'ch(HsReq)) : 'ch(HsWire_t) {
        #import {sig #[ EVAL_T ] : 'ch(EvalIn) → 'ch(TransKey)} as eval_t ;;
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys)} as chan ;;
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
      #def #[ REQUEST_A ] (rq : 'ch(Req)) : 'ch(chOption AnsWire_t) {
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys)} as chan ;;
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
      #def #[ TEST ] (ti : 'ch(TestIn)) : 'ch(chOption SessionKey) {
        #import {sig #[ SESSION_KEY ] : 'ch(TestIn) → 'ch(chOption SessionKey)} as session_key ;;
        r ← session_key ti ;;
        match r with
        | None => ret None
        | Some ks =>
            fresh ← sample uniform (2 ^ session_bits) ;;
            ret (Some (exported replace fresh ks))
        end
      } ;
      #def #[ CHAL_P ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED_P ] (s : 'ch(Solved_t)) : 'ch(chOption HsWire_t) {
        #import {sig #[ EVAL_T ] : 'ch(EvalIn) → 'ch(TransKey)} as eval_t ;;
        #import {sig #[ CHAN ] : 'nat → 'ch(ChanKeys)} as chan ;;
        mm ← get pmkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put pmkey_loc := Some k ;;
                        ret k
              end) ;;
        if puzzle_check (puzzle_mac km s.1.1) s then
          L ← get cache_loc ;;
          match L (label_of s) with
          | Some v =>
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          | None =>
              D ← get dmap_loc ;;
              ref ← (match D s.2.2.2.2 with
                     | Some i => ret (Some i, no_key)
                     | None =>
                         ms ← get seed_loc ;;
                         sd ← (match ms with
                               | Some s => ret s
                               | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                                         #put seed_loc := Some s ;;
                                         ret s
                               end) ;;
                         ret (None, mlkem_decaps sd s.2.2.2.2)
                     end) ;;
              m ← sample uniform (2 ^ msg_bits) ;;
              sa ← sample uniform (2 ^ salt_bits) ;;
              cookie ← sample uniform (2 ^ cookie_bits) ;;
              let K := (fo_derive s.2.2.1 m sa).1 in
              keys ← (match ref.1 with
                      | Some i =>
                          kt ← eval_t (i, K) ;;
                          ch ← chan i ;;
                          ret (kt, ch)
                      | None => ret ((kdf K ref.2).2, chan_keys ref.2)
                      end) ;;
              Sd ← get side_loc ;;
              #put side_loc := setm Sd cookie
                ((fo_derive s.2.2.1 m sa).2, (m, (s.2.2.2.1, ref))) ;;
              let v := (cookie, (sa, (keys.1, keys.2))) in
              #put cache_loc := setm L (label_of s) v ;;
              rn ← sample uniform (2 ^ reply_nonce_bits) ;;
              ret (Some (reply_of s.2.2 v rn))
          end
        else ret None
      }
    ].

  Ltac sync_step :=
    first
      [ ssprove_sync_eq => ?
      | ssprove_sync_eq
      | match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            case: mk => [?|] /=
        end
      | match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end ];
    try (progress cbv zeta).

  Ltac close_same :=
    eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].

  #[local] Notation KeySepReal_a :=
    (KeySepReal cookie_key_bits cookie_nonce_bits cookie_bits mac_key_bits coins_key_bits
       coins_bits CookiePlain MacIn_t PuzzleTag_t CoinsIn_t seal_cookie open_cookie mac_key_of
       coins_key_of puzzle_mac puzzle_coins).
  #[local] Notation KeySepIdeal_a :=
    (KeySepIdeal cookie_key_bits cookie_nonce_bits cookie_bits mac_key_bits coins_key_bits
       coins_bits CookiePlain MacIn_t PuzzleTag_t CoinsIn_t seal_cookie open_cookie puzzle_mac
       puzzle_coins).
  #[local] Notation CcaReal_a :=
    (CcaReal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation CcaIdeal_a :=
    (CcaIdeal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation AeadReal :=
    (CookieAeadReal cookie_key_bits cookie_nonce_bits cookie_bits CookiePlain seal_cookie open_cookie).
  #[local] Notation AeadIdeal :=
    (CookieAeadIdeal cookie_key_bits cookie_nonce_bits cookie_bits CookiePlain seal_cookie).
  #[local] Notation RandReal :=
    (CookieRandReal auth_bits cookie_key_bits cookie_nonce_bits cookie_bits msg_bits HSeed_t
       Theta_t seal_cookie).
  #[local] Notation RandIdeal := (CookieRandIdeal auth_bits cookie_bits msg_bits HSeed_t Theta_t).
  #[local] Notation PrfReal_a := (PrfReal auth_bits session_bits transcript_bits chan_bits Key_t kdf chan_keys).
  #[local] Notation PrfIdeal_a := (PrfIdeal auth_bits session_bits transcript_bits chan_bits Key_t kdf chan_keys).

  Definition cache_rel (kk : 'option CookieKey) (ms : 'option MlkemSeed)
    (L : chMap Label_t Cached_t) : Prop :=
    ∀ l v, L l = Some v → ∃ ck sd, kk = Some ck ∧ ms = Some sd ∧ v = solve_val ck ck sd l.

  Notation cache_inv :=
    (heap_ignore [fmap cache_loc] ⋊
     rel_app [:: (lhs, ckey_loc) ; (lhs, seed_loc) ; (rhs, cache_loc)] cache_rel).

  Lemma cache_rel_init_ckey ms L k : cache_rel None ms L → cache_rel (Some k) ms L.
  Proof. move=> H l v /H [ck [sd [E _]]]; discriminate. Qed.

  Lemma cache_rel_init_seed kk L s : cache_rel kk None L → cache_rel kk (Some s) L.
  Proof. move=> H l v /H [ck [sd [_ [E _]]]]; discriminate. Qed.

  Lemma cache_rel_set k sd L l :
    cache_rel (Some k) (Some sd) L →
    cache_rel (Some k) (Some sd) (setm L l (solve_val k k sd l)).
  Proof.
    move=> H l' v; rewrite setmE; case: eqP => [-> [<-]|_ /H //].
    by exists k, sd.
  Qed.

  Ltac heap_simpl :=
    repeat first
      [ rewrite -> get_set_heap_eq
      | rewrite -> get_set_heap_neq by done ].

  Ltac side_init :=
    let s0 := fresh "s0" in let s1 := fresh "s1" in let H := fresh "H" in
    move=> s0 s1 H;
    rewrite /inv_conj in H *;
    repeat match goal with Hc : _ ∧ _ |- _ => destruct Hc end;
    repeat split;
    unfold rem_inv in *;
    rewrite -> ?rel_app_cons in *; rewrite -> ?rel_app_nil in *;
    unfold get_side in *; simpl in *;
    heap_simpl;
    first
      [ by apply: heap_ignore_set_both
      | done
      | match goal with
        | Hr : cache_rel _ _ _ |- _ =>
            repeat match goal with
              | E : get_heap _ _ = _ |- _ => (try rewrite E in Hr); (try rewrite E); clear E
              end;
            first [ by apply: cache_rel_init_ckey | by apply: cache_rel_init_seed | done ]
        end ].

  Ltac remind_ck side k :=
    match side with
    | lhs => eapply (@r_get_remind_lhs _ _ ckey_loc (Some k)); try exact _; ssprove_code_simpl
    | rhs => eapply (@r_get_remind_rhs _ _ ckey_loc (Some k)); try exact _; ssprove_code_simpl
    end.

  Ltac solved_hit k HL :=
    let Hrel := fresh "Hrel" in
    apply: r_get_remember_lhs => ms;
    ssprove_rem_rel 0%N; intro Hrel;
    case: (Hrel _ _ HL) => ck [sd [[<-] [-> ->]]] /=;
    remind_ck lhs k; remind_ck lhs k;
    ssprove_forget_all;
    ssprove_sync => rn;
    apply: r_ret => s0 s1 H; by split.

  Ltac lazy_both :=
    let kk := fresh "kk" in let k := fresh "k" in
    get_both kk; case: kk => [k|];
    [ ssprove_forget_all
    | ssprove_code_simpl; cbn [bind]; ssprove_sync; intro k; apply: r_put_vs_put;
      apply: (r_set_both_weaken _ _ _ cache_inv); [ side_init | ] ].

  Ltac step0 :=
    ssprove_code_simpl; cbn [bind]; try (progress cbv zeta);
    first
      [ apply: r_ret => s0 s1 H; by split
      | match goal with
        | |- ⊢ ⦃ _ ⦄ _ ≈ (x ← get ckey_loc ;; _) ⦃ _ ⦄ => lazy_both
        | |- ⊢ ⦃ _ ⦄ _ ≈ (x ← get seed_loc ;; _) ⦃ _ ⦄ => lazy_both
        end
      | ssprove_sync => ?
      | ssprove_sync
      | match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end ].

  Lemma active_p_is_keysep_reduction b : ActiveP b ≈₀ (R_ks b ∘ KeySepReal_a)%pack.
  Proof.
    eapply eq_rel_perf_ind with cache_inv.
    { ssprove_invariant. rewrite /rel_empty /=. by move=> l v; rewrite emptymE. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    6: { get_both kk.
         case: kk => [k|]; last first.
         1: ssprove_sync => k.
         1: apply: r_put_vs_put.
         1: apply: (r_set_both_weaken _ _ _ (cache_inv ⋊ rem_lhs ckey_loc (Some k) ⋊ rem_rhs ckey_loc (Some k))).
         1: side_init.
         { cbv zeta.
           case: (puzzle_check _ _) => /=; last first.
           { ssprove_forget_all; apply: r_ret => s0 s1 H; by split. }
           apply: r_get_remember_rhs => L.
           case HL: (L (label_of x)) => [v|] /=.
           { solved_hit k HL. }
           get_both ms.
           case: ms => [sd|]; last first.
           1: ssprove_code_simpl; cbn [bind].
           1: ssprove_sync => sd.
           1: apply: r_put_vs_put.
           1: apply: (r_set_both_weaken _ _ _ (cache_inv ⋊ rem_lhs ckey_loc (Some k) ⋊ rem_rhs ckey_loc (Some k) ⋊ rem_rhs cache_loc L ⋊ rem_lhs seed_loc (Some sd) ⋊ rem_rhs seed_loc (Some sd))).
           1: side_init.
           all: ssprove_code_simpl.
           all: remind_ck lhs k.
           all: remind_ck lhs k.
           all: remind_ck rhs k.
           all: remind_ck rhs k.
           all: apply: r_put_rhs.
           all: ssprove_restore_mem; [ rewrite ?catA /=; ssprove_invariant; move=> ?; by apply: cache_rel_set | ].
           all: ssprove_sync => rn.
           all: apply: r_ret => s0 s1 H; by split. }
         { cbv zeta.
           case: (puzzle_check _ _) => /=; last first.
           { ssprove_forget_all; apply: r_ret => s0 s1 H; by split. }
           apply: r_get_remember_rhs => L.
           case HL: (L (label_of x)) => [v|] /=.
           { solved_hit k HL. }
           get_both ms.
           case: ms => [sd|]; last first.
           1: ssprove_code_simpl; cbn [bind].
           1: ssprove_sync => sd.
           1: apply: r_put_vs_put.
           1: apply: (r_set_both_weaken _ _ _ (cache_inv ⋊ rem_lhs ckey_loc (Some k) ⋊ rem_rhs ckey_loc (Some k) ⋊ rem_rhs cache_loc L ⋊ rem_lhs seed_loc (Some sd) ⋊ rem_rhs seed_loc (Some sd))).
           1: side_init.
           all: ssprove_code_simpl.
           all: remind_ck lhs k.
           all: remind_ck lhs k.
           all: remind_ck rhs k.
           all: remind_ck rhs k.
           all: apply: r_put_rhs.
           all: ssprove_restore_mem; [ rewrite ?catA /=; ssprove_invariant; move=> ?; by apply: cache_rel_set | ].
           all: ssprove_sync => rn.
           all: apply: r_ret => s0 s1 H; by split. } }

    all: repeat step0.
  Qed.

  Lemma keysep_ideal_is_coins_reduction b :
    (R_ks b ∘ KeySepIdeal_a)%pack ≈₀ (R_co b ∘ CoinsSplitReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma coins_ideal_is_cr_reduction b :
    (R_co b ∘ CoinsSplitIdeal)%pack ≈₀ (R_cr b ∘ CrReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma ideal_int_is_ind_reduction_p b :
    (R_intp b ∘ AeadIdeal)%pack ≈₀ (R_indp b ∘ RandReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: repeat sync_step.
    all: try close_same.
  Qed.


  Definition cr_rel (T : chMap CoinsIn_t Split_t) (H : chMap Digest_t HsReq)
    (L : chMap Label_t Cached_t) : Prop :=
    ∀ n d sp, T (n, d) = Some sp → ∃ x, H d = Some x ∧ isSome (L (n, x)).

  Definition cr_pend (l : Label_t) (T : chMap CoinsIn_t Split_t) (H : chMap Digest_t HsReq)
    (L : chMap Label_t Cached_t) : Prop :=
    ∀ n d sp, T (n, d) = Some sp → ∃ x, H d = Some x ∧ (orb (isSome (L (n, x))) ((n, x) == l)).

  Lemma cr_pend_of_rel l T H L : cr_rel T H L → cr_pend l T H L.
  Proof. move=> Hr n d sp /Hr [x [Hx HL]]; exists x; by rewrite Hx HL. Qed.

  Lemma cr_rel_of_pend l T H L v : cr_pend l T H L → cr_rel T H (setm L l v).
  Proof.
    move=> Hp n d sp /Hp [x [Hx HL]]; exists x; split => //.
    rewrite setmE; case: eqP => // Hne; case/orP: HL => // /eqP E; by case: Hne.
  Qed.

  Lemma cr_table_fresh_known T H L n d x :
    cr_rel T H L → H d = Some x → L (n, x) = None → T (n, d) = None.
  Proof.
    move=> Hr Hx HL; case E: (T (n, d)) => [sp|] //.
    case: (Hr _ _ _ E) => y [Hy HLy]; rewrite Hx in Hy; case: Hy => Hy; subst y; by rewrite HL in HLy.
  Qed.

  Lemma cr_table_fresh_new T H L n d :
    cr_rel T H L → H d = None → T (n, d) = None.
  Proof.
    move=> Hr Hx; case E: (T (n, d)) => [sp|] //.
    case: (Hr _ _ _ E) => y [Hy _]; by rewrite Hx in Hy.
  Qed.

  Lemma cr_pend_set_known T H L n d x sp :
    cr_rel T H L → H d = Some x → cr_pend (n, x) (setm T (n, d) sp) H L.
  Proof.
    move=> Hr Hx n' d' sp'; rewrite setmE; case: eqP => [[-> ->] _|_ /Hr [y [Hy HL]]].
    - exists x; by rewrite Hx eqxx orbT.
    - exists y; by rewrite Hy HL.
  Qed.

  Lemma cr_pend_set_new T H L n d x sp :
    cr_rel T H L → H d = None → cr_pend (n, x) (setm T (n, d) sp) (setm H d x) L.
  Proof.
    move=> Hr Hx n' d' sp'; rewrite setmE; case: eqP => [[-> ->] _|Hne /Hr [y [Hy HL]]].
    - exists x; by rewrite setmE eqxx eqxx orbT.
    - exists y; rewrite setmE; case: eqP => [E|_]; last by rewrite Hy HL.
      by rewrite E Hx in Hy.
  Qed.

  Lemma heap_ignore_set_lhs_in (L : Locations) (ℓ : Location) (v : ℓ) s₀ s₁ :
    fhas L ℓ → heap_ignore L (s₀, s₁) → heap_ignore L (set_heap s₀ ℓ v, s₁).
  Proof.
    move=> Hin H ℓ₀ hℓ₀.
    case E: (ℓ₀.1 != ℓ.1).
    - rewrite get_set_heap_neq //. exact: H.
    - move: E => /negbFE /eqP E.
      move: hℓ₀ => /dommPn; rewrite E.
      destruct ℓ as [t n]; rewrite /= Hin //.
  Qed.

  Lemma r_set_lhs_weaken {A B : choiceType} (ℓ : Location) (v : ℓ) (P Q : precond)
    (c₀ : raw_code A) (c₁ : raw_code B) (post : postcond A B) :
    (∀ s₀ s₁, P (s₀, s₁) → Q (set_heap s₀ ℓ v, s₁)) →
    ⊢ ⦃ λ '(s₀, s₁), Q (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄ →
    ⊢ ⦃ λ '(s₀, s₁), set_lhs ℓ v P (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄.
  Proof.
    move=> HPQ H.
    eapply rpre_weaken_rule; first exact: H.
    move=> s₀ s₁ [s₀' [HP ->]]. exact: HPQ.
  Qed.

  Lemma r_set_lhs2_weaken {A B : choiceType} (ℓ₁ ℓ₂ : Location) (v₁ : ℓ₁) (v₂ : ℓ₂)
    (P Q : precond) (c₀ : raw_code A) (c₁ : raw_code B) (post : postcond A B) :
    (∀ s₀ s₁, P (s₀, s₁) → Q (set_heap (set_heap s₀ ℓ₁ v₁) ℓ₂ v₂, s₁)) →
    ⊢ ⦃ λ '(s₀, s₁), Q (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄ →
    ⊢ ⦃ λ '(s₀, s₁), set_lhs ℓ₂ v₂ (set_lhs ℓ₁ v₁ P) (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄.
  Proof.
    move=> HPQ H.
    eapply rpre_weaken_rule; first exact: H.
    move=> s₀ s₁ [s₀' [[s₀'' [HP ->]] ->]]. exact: HPQ.
  Qed.

  Lemma r_pre_weaken_to {A B : choiceType} (P Q : precond)
    (c₀ : raw_code A) (c₁ : raw_code B) (post : postcond A B) :
    (∀ s₀ s₁, P (s₀, s₁) → Q (s₀, s₁)) →
    ⊢ ⦃ λ '(s₀, s₁), Q (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄ →
    ⊢ ⦃ λ '(s₀, s₁), P (s₀, s₁) ⦄ c₀ ≈ c₁ ⦃ post ⦄.
  Proof. move=> HPQ H; eapply rpre_weaken_rule; first exact: H. exact: HPQ. Qed.

  Notation cr_inv :=
    (heap_ignore [fmap coins3_loc ; hash_loc] ⋊
     rel_app [:: (lhs, coins3_loc) ; (lhs, hash_loc) ; (lhs, cache_loc)] cr_rel).

  Notation cr_pinv l L :=
    (heap_ignore [fmap coins3_loc ; hash_loc] ⋊
     rel_app [:: (lhs, coins3_loc) ; (lhs, hash_loc) ; (lhs, cache_loc)] (cr_pend l) ⋊
     rem_lhs cache_loc L ⋊ rem_rhs cache_loc L).

  Ltac unfold_pre :=
    rewrite /inv_conj;
    repeat match goal with Hc : _ ∧ _ |- _ => destruct Hc end;
    repeat split;
    unfold rem_inv in *;
    rewrite -> ?rel_app_cons in *; rewrite -> ?rel_app_nil in *;
    unfold get_side in *; simpl in *;
    heap_simpl.

  Ltac step_inv :=
    ssprove_code_simpl; cbn [bind]; try (progress cbv zeta);
    first
      [ apply: r_ret => s0 s1 H; by split
      | ssprove_sync => ?
      | ssprove_sync; [ ssprove_invariant | ]
      | ssprove_sync
      | match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            case: mk => [?|] /=
        end
      | match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end ].

  Ltac side_cr :=
    let s0 := fresh "s0" in let s1 := fresh "s1" in let H := fresh "H" in
    move=> s0 s1 H;
    rewrite /inv_conj in H *;
    repeat match goal with Hc : _ ∧ _ |- _ => destruct Hc end;
    repeat split;
    unfold rem_inv in *;
    rewrite -> ?rel_app_cons in *; rewrite -> ?rel_app_nil in *;
    unfold get_side in *; simpl in *;
    heap_simpl;
    first
      [ by apply: heap_ignore_set_both
      | (do 2 (apply: heap_ignore_set_lhs_in; [ rewrite /fhas; reflexivity | ]); assumption)
      | (apply: heap_ignore_set_lhs_in; [ rewrite /fhas; reflexivity | assumption ])
      | done
      | match goal with
        | Hr : cr_rel _ _ _ |- _ =>
            repeat match goal with
              | E : get_heap _ _ = _ |- _ => (try rewrite E in Hr); (try rewrite E); clear E
              end;
            first [ by apply: cr_pend_of_rel | by apply: cr_pend_set_known
                  | by apply: cr_pend_set_new ]
        | Hr : cr_pend _ _ _ _ |- _ =>
            repeat match goal with
              | E : get_heap _ _ = _ |- _ => (try rewrite E in Hr); (try rewrite E); clear E
              end;
            by apply: cr_rel_of_pend
        end ].

  Lemma cr_ideal_is_cca_reduction b : (R_cr b ∘ CrIdeal)%pack ≈₀ (R_ccap b ∘ CcaReal_a)%pack.
  Proof.
    eapply eq_rel_perf_ind with cr_inv.
    { ssprove_invariant. rewrite /rel_empty /=. by move=> n d sp; rewrite emptymE. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    6: { ssprove_sync => mm.
         case: mm => [km|] /=; [ idtac | ssprove_sync => km; ssprove_sync ].
         all: ssprove_code_simpl; try (progress cbv zeta).
         all: case: (puzzle_check _ _) => /=; [ idtac | by apply: r_ret => s0 s1 H; split ].
         all: get_both L.
         all: case HL: (L (label_of x)) => [v|] /=;
           [ ssprove_forget_all; ssprove_sync => rn; apply: r_ret => s0 s1 H; by split | idtac ].
         all: ssprove_sync => ms.
         all: case: ms => [sd|] /=; [ idtac | ssprove_sync => sd; ssprove_sync ].
         all: ssprove_code_simpl.
         all: apply: r_get_remember_lhs => H.
         all: case HH: (H (digest x.2.2)) => [x'|] /=;
           [ case Ex: (x' == x.2.2)%B => /=;
             [ move/eqP: Ex => Ex; subst x';
               apply: r_get_remember_lhs => T;
               ssprove_rem_rel 0%N => Hcr;
               rewrite (cr_table_fresh_known _ _ _ _ _ _ Hcr HH HL) /=;
               ssprove_code_simpl; ssprove_sync => m; ssprove_sync => sa; ssprove_sync => nn;
               apply: r_put_lhs;
               apply: (r_set_lhs_weaken _ _ _ (cr_pinv (label_of x) L)); [ side_cr | ]
             | ssprove_code_simpl; ssprove_sync => m; ssprove_sync => sa; ssprove_sync => nn;
               apply: (r_pre_weaken_to _ (cr_pinv (label_of x) L)); [ side_cr | ] ]
           | ssprove_swap_lhs 0%N;
             apply: r_get_remember_lhs => T;
             ssprove_rem_rel 0%N => Hcr;
             rewrite (cr_table_fresh_new _ _ _ _ _ Hcr HH) /=;
             ssprove_code_simpl;
             apply: r_put_lhs;
             ssprove_sync => m; ssprove_sync => sa; ssprove_sync => nn;
             apply: r_put_lhs;
             apply: (r_set_lhs2_weaken _ _ _ _ _ (cr_pinv (label_of x) L)); [ side_cr | ] ].
         all: ssprove_sync => kk.
         all: case: kk => [k|] /=; [ idtac | ssprove_sync => k; ssprove_sync ].
         all: apply: r_put_vs_put.
         all: apply: (r_set_both_weaken _ _ _ cr_inv); [ side_cr | ].
         all: ssprove_sync => rn.
         all: apply: r_ret => s0 s1 H0; by split. }
    all: repeat step_inv.
  Qed.

  Ltac sync_step2 :=
    first
      [ ssprove_sync_eq => ?
      | ssprove_sync_eq
      | match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            case: mk => [?|] /=
        end
      | match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end
      | lazymatch goal with
        | |- ⊢ ⦃ _ ⦄ (x ← sample _ ;; _) ≈ (y ← get _ ;; _) ⦃ _ ⦄ => ssprove_swap_lhs 0%N
        | |- ⊢ ⦃ _ ⦄ (x ← sample _ ;; _) ≈ (y ← sample _ ;; _) ⦃ _ ⦄ => ssprove_swap_lhs 0%N
        | |- ⊢ ⦃ _ ⦄ (x ← sample _ ;; _) ≈ (#put _ := _ ;; _) ⦃ _ ⦄ => ssprove_swap_rhs 0%N
        end ];
    try (progress cbv zeta).

  Lemma ideal_cca_is_int_reduction_p b : (R_ccap b ∘ CcaIdeal_a)%pack ≈₀ (R_intp b ∘ AeadReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: repeat sync_step2.
    all: try close_same.
  Qed.

  #[local] Notation cd_agree := (chal_dmap_agree auth_bits McCt_t).
  #[local] Notation cd_keys := (chal_dmap_keys auth_bits McCt_t).
  #[local] Notation is_agree := (issued_side_agree auth_bits cookie_bits msg_bits HSeed_t Theta_t).
  #[local] Notation is_keys := (issued_side_keys auth_bits cookie_bits msg_bits HSeed_t Theta_t).

  Notation repr_inv_p :=
    (heap_ignore [fmap cchal_loc ; cissued_loc ; dmap_loc ; side_loc] ⋊
     rel_app [:: (lhs, cchal_loc) ; (rhs, dmap_loc)] cd_agree ⋊
     rel_app [:: (lhs, cchal_loc) ; (rhs, dmap_loc) ; (rhs, kmap_loc)] cd_keys ⋊
     rel_app [:: (lhs, cissued_loc) ; (rhs, side_loc)] is_agree ⋊
     rel_app [:: (lhs, cissued_loc) ; (rhs, side_loc) ; (rhs, kmap_loc)] is_keys).

  Ltac close_side :=
    first
      [ let H := fresh "H" in
        move=> H;
        apply: (issued_side_agree_set auth_bits cookie_bits msg_bits HSeed_t Theta_t _ _ _ _ _ H) => /=;
        first [ intros; discriminate | reflexivity ]
      | let H := fresh "H" in
        move=> H;
        apply: (issued_side_keys_set auth_bits cookie_bits msg_bits HSeed_t Theta_t _ _ _ _ _ _ H) => /=;
        first [ intros; discriminate | move=> ? [<-]; by split ] ].

  Lemma ideal_ind_is_prf_reduction_p b : (R_indp b ∘ RandIdeal)%pack ≈₀ (R_prfp b ∘ PrfReal_a)%pack.
  Proof.
    eapply eq_rel_perf_ind with repr_inv_p.
    { ssprove_invariant => //. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    all: try (progress cbv zeta).
    all: ssprove_code_simpl.
    6: { ssprove_sync => mm.
         case: mm => [km|] /=; [ idtac | ssprove_sync => km; ssprove_sync ].
         all: ssprove_code_simpl; try (progress cbv zeta).
         all: case: (puzzle_check _ _) => /=; [ idtac | by apply: r_ret => s0 s1 H; split ].
         all: ssprove_sync => L.
         all: case HL: (L (label_of x)) => [v|] /=;
           [ ssprove_sync => rn; apply: r_ret => s0 s1 H; by split | idtac ].
         all: apply: r_get_remember_lhs => C.
         all: apply: r_get_remember_rhs => D.
         all: ssprove_rem_rel 3%N => HA1.
         all: have Hag := HA1 x.2.2.2.2.
         all: case HC: (C x.2.2.2.2) => [k|]; case HD: (D x.2.2.2.2) => [i|] /=;
              rewrite HC HD /= in Hag; try discriminate.
         - ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
           apply: r_get_remember_lhs => T.
           ssprove_contract_get_rhs.
           apply: r_get_remember_rhs => K.
           apply: r_get_remember_rhs => Sd.
           ssprove_rem_rel 2%N => HA2.
           case: (HA2 _ _ HD) => Hi; rewrite HC => -[Hk]. subst k.
           apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
           ssprove_restore_mem.
           + ssprove_invariant. all: close_side.
           + ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
         - get_both ms.
           case: ms => [s|] /=.
           + ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
             apply: r_get_remember_lhs => T.
             apply: r_get_remember_rhs => Sd.
             apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
             ssprove_restore_mem.
             * ssprove_invariant. all: close_side.
             * ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
           + do 2 ssprove_forget.
             ssprove_sync => s. ssprove_sync. 1: ssprove_invariant.
             ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
             apply: r_get_remember_lhs => T.
             apply: r_get_remember_rhs => Sd.
             apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
             ssprove_restore_mem.
             * ssprove_invariant. all: close_side.
             * ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
         - ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
           apply: r_get_remember_lhs => T.
           ssprove_contract_get_rhs.
           apply: r_get_remember_rhs => K.
           apply: r_get_remember_rhs => Sd.
           ssprove_rem_rel 2%N => HA2.
           case: (HA2 _ _ HD) => Hi; rewrite HC => -[Hk]. subst k.
           apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
           ssprove_restore_mem.
           + ssprove_invariant. all: close_side.
           + ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
         - get_both ms.
           case: ms => [s|] /=.
           + ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
             apply: r_get_remember_lhs => T.
             apply: r_get_remember_rhs => Sd.
             apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
             ssprove_restore_mem.
             * ssprove_invariant. all: close_side.
             * ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
           + do 2 ssprove_forget.
             ssprove_sync => s. ssprove_sync. 1: ssprove_invariant.
             ssprove_sync => m. ssprove_sync => sa. ssprove_sync => ck.
             apply: r_get_remember_lhs => T.
             apply: r_get_remember_rhs => Sd.
             apply: r_put_lhs. apply: r_put_rhs. apply: r_put_vs_put.
             ssprove_restore_mem.
             * ssprove_invariant. all: close_side.
             * ssprove_sync => rn. apply: r_ret => s0 s1 Hinv; by split.
         }
    all: try (progress cbv zeta).
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
    - ssprove_sync => mm.
      case: mm => [km|] /=.
      + by apply: r_ret.
      + ssprove_sync => km. ssprove_sync. by apply: r_ret.
  Qed.

  Lemma replaced_session_key_is_uniform_p :
    (R_prfp false ∘ PrfIdeal_a)%pack ≈₀ (R_prfp true ∘ PrfIdeal_a)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    4: { ssprove_sync_eq => T. ssprove_sync_eq => K.
         case: (untestable T K x.1) => /=.
         - by apply: r_ret.
         - ssprove_sync_eq.
           ssprove_swap_lhs 0%N.
           ssprove_sync_eq => ?. ssprove_sync_eq => ?.
           apply: r_ret => s0 s1 ->. by split. }
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Definition puzzle_locs : Locations :=
    [fmap seed_loc ; ckey_loc ; kmap_loc ; tested_loc ; cchal_loc ; cissued_loc ;
          dmap_loc ; side_loc ; ttab_loc ; ctab_loc ; pmkey_loc ; pckoins_loc ;
          cache_loc ; coins3_loc ; hash_loc].

  Ltac solve_puzzle_sep :=
    lazymatch goal with
    | H : fseparate ?LA puzzle_locs |- fseparate ?LA _ =>
        apply: (fsep_sub _ _ _ H); fmap_solve
    end.

  Theorem active_puzzle_hops b :
    ∀ LA A,
      ValidPackage LA I_active_p A_export A →
      fseparate LA puzzle_locs →
      AdvantageE (ActiveP b) (R_prfp b ∘ PrfIdeal_a)%pack A
      <= AdvantageE KeySepReal_a KeySepIdeal_a (A ∘ R_ks b)%pack
         + AdvantageE CoinsSplitReal CoinsSplitIdeal (A ∘ R_co b)%pack
         + AdvantageE CrReal CrIdeal (A ∘ R_cr b)%pack
         + AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_ccap b)%pack
         + AdvantageE AeadReal AeadIdeal (A ∘ R_intp b)%pack
         + AdvantageE RandReal RandIdeal (A ∘ R_indp b)%pack
         + AdvantageE PrfReal_a PrfIdeal_a (A ∘ R_prfp b)%pack.
  Proof.
    move=> LA A VA Hsep.
    ssprove triangle (ActiveP b) [::
      (R_ks b ∘ KeySepReal_a)%pack ;
      (R_ks b ∘ KeySepIdeal_a)%pack ;
      (R_co b ∘ CoinsSplitReal)%pack ;
      (R_co b ∘ CoinsSplitIdeal)%pack ;
      (R_cr b ∘ CrReal)%pack ;
      (R_cr b ∘ CrIdeal)%pack ;
      (R_ccap b ∘ CcaReal_a)%pack ;
      (R_ccap b ∘ CcaIdeal_a)%pack ;
      (R_intp b ∘ AeadReal)%pack ;
      (R_intp b ∘ AeadIdeal)%pack ;
      (R_indp b ∘ RandReal)%pack ;
      (R_indp b ∘ RandIdeal)%pack ;
      (R_prfp b ∘ PrfReal_a)%pack
    ] (R_prfp b ∘ PrfIdeal_a)%pack A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z0 : AdvantageE (ActiveP b) (R_ks b ∘ KeySepReal_a)%pack A = 0.
    { apply: active_p_is_keysep_reduction; solve_puzzle_sep. }
    have Z1 : AdvantageE (R_ks b ∘ KeySepIdeal_a)%pack (R_co b ∘ CoinsSplitReal)%pack A = 0.
    { apply: keysep_ideal_is_coins_reduction; solve_puzzle_sep. }
    have Z2 : AdvantageE (R_co b ∘ CoinsSplitIdeal)%pack (R_cr b ∘ CrReal)%pack A = 0.
    { apply: coins_ideal_is_cr_reduction; solve_puzzle_sep. }
    have Z3 : AdvantageE (R_cr b ∘ CrIdeal)%pack (R_ccap b ∘ CcaReal_a)%pack A = 0.
    { apply: cr_ideal_is_cca_reduction; solve_puzzle_sep. }
    have Z4 : AdvantageE (R_ccap b ∘ CcaIdeal_a)%pack (R_intp b ∘ AeadReal)%pack A = 0.
    { apply: ideal_cca_is_int_reduction_p; solve_puzzle_sep. }
    have Z5 : AdvantageE (R_intp b ∘ AeadIdeal)%pack (R_indp b ∘ RandReal)%pack A = 0.
    { apply: ideal_int_is_ind_reduction_p; solve_puzzle_sep. }
    have Z6 : AdvantageE (R_indp b ∘ RandIdeal)%pack (R_prfp b ∘ PrfReal_a)%pack A = 0.
    { apply: ideal_ind_is_prf_reduction_p; solve_puzzle_sep. }
    rewrite Z0 Z1 Z2 Z3 Z4 Z5 Z6 GRing.add0r !GRing.addr0.
    by rewrite !Advantage_link.
  Qed.

  Theorem active_puzzle_session_key_secrecy :
    ∀ LA A,
      ValidPackage LA I_active_p A_export A →
      fseparate LA puzzle_locs →
      AdvantageE (ActiveP false) (ActiveP true) A
      <= (AdvantageE KeySepReal_a KeySepIdeal_a (A ∘ R_ks false)%pack
          + AdvantageE CoinsSplitReal CoinsSplitIdeal (A ∘ R_co false)%pack
          + AdvantageE CrReal CrIdeal (A ∘ R_cr false)%pack
          + AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_ccap false)%pack
          + AdvantageE AeadReal AeadIdeal (A ∘ R_intp false)%pack
          + AdvantageE RandReal RandIdeal (A ∘ R_indp false)%pack
          + AdvantageE PrfReal_a PrfIdeal_a (A ∘ R_prfp false)%pack)
         + (AdvantageE KeySepReal_a KeySepIdeal_a (A ∘ R_ks true)%pack
            + AdvantageE CoinsSplitReal CoinsSplitIdeal (A ∘ R_co true)%pack
            + AdvantageE CrReal CrIdeal (A ∘ R_cr true)%pack
            + AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_ccap true)%pack
            + AdvantageE AeadReal AeadIdeal (A ∘ R_intp true)%pack
            + AdvantageE RandReal RandIdeal (A ∘ R_indp true)%pack
            + AdvantageE PrfReal_a PrfIdeal_a (A ∘ R_prfp true)%pack).
  Proof.
    move=> LA A VA Hsep.
    ssprove triangle (ActiveP false) [::
      (R_prfp false ∘ PrfIdeal_a)%pack ;
      (R_prfp true ∘ PrfIdeal_a)%pack
    ] (ActiveP true) A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z : AdvantageE (R_prfp false ∘ PrfIdeal_a)%pack (R_prfp true ∘ PrfIdeal_a)%pack A = 0.
    { apply: replaced_session_key_is_uniform_p; solve_puzzle_sep. }
    rewrite Z GRing.addr0 [AdvantageE _ (ActiveP true) _]Advantage_sym.
    apply: Num.Theory.lerD.
    - exact: active_puzzle_hops VA Hsep.
    - exact: active_puzzle_hops VA Hsep.
  Qed.

  #[local] Notation CcaStdReal_a :=
    (CcaStdReal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation CcaStdIdeal_a :=
    (CcaStdIdeal mlkem_key_bits mlkem_coin_bits auth_bits McPK_t McCt_t mlkem_pk mlkem_encaps mlkem_decaps).
  #[local] Notation R_std_a := (R_std auth_bits McPK_t McCt_t).

  Context (mlkem_correct : ∀ s r,
    mlkem_decaps s (mlkem_encaps (mlkem_pk s) r).1 = (mlkem_encaps (mlkem_pk s) r).2).

  Lemma cca_term_std_p b LA A :
    ValidPackage LA I_active_p A_export A →
    fseparate LA puzzle_locs →
    fseparate LA [fmap refuse_loc McCt_t] →
    AdvantageE CcaReal_a CcaIdeal_a (A ∘ R_ccap b)%pack
    <= AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_ccap b) ∘ R_std_a)%pack.
  Proof.
    move=> VA Hsep Href.
    unshelve eapply (cca_from_standard _ _ _ _ _ _ _ _ mlkem_correct _ _).
    1: exact (unionm LA [fmap ckey_loc ; pmkey_loc ; kmap_loc ; tested_loc ; cache_loc]).
    1: ssprove_valid.
    - apply: fseparate_compat; rewrite /=; solve_puzzle_sep.
    - apply: fseparateUl; first solve_puzzle_sep. fmap_solve.
    - apply: fseparateUl; first solve_puzzle_sep. fmap_solve.
    - apply: fseparateUl; first done. fmap_solve.
  Qed.

  Theorem active_puzzle_session_key_secrecy_std :
    ∀ LA A,
      ValidPackage LA I_active_p A_export A →
      fseparate LA puzzle_locs →
      fseparate LA [fmap refuse_loc McCt_t] →
      AdvantageE (ActiveP false) (ActiveP true) A
      <= (AdvantageE KeySepReal_a KeySepIdeal_a (A ∘ R_ks false)%pack
          + AdvantageE CoinsSplitReal CoinsSplitIdeal (A ∘ R_co false)%pack
          + AdvantageE CrReal CrIdeal (A ∘ R_cr false)%pack
          + AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_ccap false) ∘ R_std_a)%pack
          + AdvantageE AeadReal AeadIdeal (A ∘ R_intp false)%pack
          + AdvantageE RandReal RandIdeal (A ∘ R_indp false)%pack
          + AdvantageE PrfReal_a PrfIdeal_a (A ∘ R_prfp false)%pack)
         + (AdvantageE KeySepReal_a KeySepIdeal_a (A ∘ R_ks true)%pack
            + AdvantageE CoinsSplitReal CoinsSplitIdeal (A ∘ R_co true)%pack
            + AdvantageE CrReal CrIdeal (A ∘ R_cr true)%pack
            + AdvantageE CcaStdReal_a CcaStdIdeal_a ((A ∘ R_ccap true) ∘ R_std_a)%pack
            + AdvantageE AeadReal AeadIdeal (A ∘ R_intp true)%pack
            + AdvantageE RandReal RandIdeal (A ∘ R_indp true)%pack
            + AdvantageE PrfReal_a PrfIdeal_a (A ∘ R_prfp true)%pack).
  Proof.
    move=> LA A VA Hsep Href.
    eapply Order.POrderTheory.le_trans; first exact: active_puzzle_session_key_secrecy VA Hsep.
    apply: Num.Theory.lerD; do 4 (apply: Num.Theory.lerD => //);
      exact: cca_term_std_p.
  Qed.

End ActivePuzzle.
