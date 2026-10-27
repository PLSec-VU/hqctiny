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

From SSProveHQC Require Import MLKEMCCA.

Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
Notation " 'ch ( x ) " := x (at level 2) : package_scope.

Section RequestIntegrity.

  Context (req_key_bits : nat).
  Context (ReqHdr_t ReqCookie_t ReqSealed_t ReqPayload_t ReqAnswer_t : choice_type).

  Definition ReqKey_t := chFin (2 ^ req_key_bits).
  Definition ReqNonce_t := chProd 'nat (chProd ReqHdr_t ReqCookie_t).
  Definition ReqPacket_t := chProd 'nat (chProd ReqHdr_t (chProd ReqCookie_t ReqSealed_t)).
  Definition SealIn_t := chProd 'nat (chProd ReqHdr_t (chProd ReqCookie_t ReqPayload_t)).

  Context (seal_req : ReqKey_t → ReqHdr_t → ReqCookie_t → ReqPayload_t → ReqSealed_t).
  Context (open_req : ReqKey_t → ReqHdr_t → ReqCookie_t → ReqSealed_t → option ReqPayload_t).
  Context (answer : 'nat → ReqHdr_t → ReqCookie_t → ReqPayload_t → ReqAnswer_t).

  Definition no_req_key : ReqKey_t := zero_of_bits req_key_bits.

  Definition sealed_once (N : chMap ReqNonce_t ReqPayload_t) (n : ReqNonce_t) (p : ReqPayload_t)
    : bool :=
    match N n with
    | Some p' => p' == p
    | None => true
    end.

  Definition rkeys_loc : Location := mkloc 90 ([::] : chList ReqKey_t).
  Definition rnonce_loc : Location := mkloc 91 (emptym : chMap ReqNonce_t ReqPayload_t).
  Definition rsealed_loc : Location := mkloc 92 (emptym : chMap ReqPacket_t ReqPayload_t).

  Definition NEW_CHAN : ident := 93%N.
  Definition SEAL_REQ : ident := 94%N.
  Definition OPEN_REQ : ident := 95%N.
  Definition SERVE : ident := 96%N.

  Definition I_req_aead : Interface :=
    [interface
      #val #[ NEW_CHAN ] : 'unit → 'nat ;
      #val #[ SEAL_REQ ] : 'ch(SealIn_t) → 'ch(chOption ReqSealed_t) ;
      #val #[ OPEN_REQ ] : 'ch(ReqPacket_t) → 'ch(chOption ReqPayload_t) ].

  Definition I_req_server : Interface :=
    [interface
      #val #[ NEW_CHAN ] : 'unit → 'nat ;
      #val #[ SEAL_REQ ] : 'ch(SealIn_t) → 'ch(chOption ReqSealed_t) ;
      #val #[ SERVE ] : 'ch(ReqPacket_t) → 'ch(chOption ReqAnswer_t) ].

  Definition ReqAeadReal : package emptym I_req_aead :=
    [package [fmap rkeys_loc ; rnonce_loc] ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ req_key_bits) ;;
        K ← get rkeys_loc ;;
        #put rkeys_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn_t)) : 'ch(chOption ReqSealed_t) {
        K ← get rkeys_loc ;;
        N ← get rnonce_loc ;;
        let n := (q.1, (q.2.1, q.2.2.1)) in
        if (q.1 < size K)%N && sealed_once N n q.2.2.2 then
          #put rnonce_loc := setm N n q.2.2.2 ;;
          ret (Some (seal_req (nth no_req_key K q.1) q.2.1 q.2.2.1 q.2.2.2))
        else ret None
      } ;
      #def #[ OPEN_REQ ] (x : 'ch(ReqPacket_t)) : 'ch(chOption ReqPayload_t) {
        K ← get rkeys_loc ;;
        if (x.1 < size K)%N then
          ret (open_req (nth no_req_key K x.1) x.2.1 x.2.2.1 x.2.2.2)
        else ret None
      }
    ].

  Definition ReqAeadIdeal : package emptym I_req_aead :=
    [package [fmap rkeys_loc ; rnonce_loc ; rsealed_loc] ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ req_key_bits) ;;
        K ← get rkeys_loc ;;
        #put rkeys_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn_t)) : 'ch(chOption ReqSealed_t) {
        K ← get rkeys_loc ;;
        N ← get rnonce_loc ;;
        let n := (q.1, (q.2.1, q.2.2.1)) in
        if (q.1 < size K)%N && sealed_once N n q.2.2.2 then
          #put rnonce_loc := setm N n q.2.2.2 ;;
          let x := seal_req (nth no_req_key K q.1) q.2.1 q.2.2.1 q.2.2.2 in
          T ← get rsealed_loc ;;
          #put rsealed_loc := setm T (q.1, (q.2.1, (q.2.2.1, x))) q.2.2.2 ;;
          ret (Some x)
        else ret None
      } ;
      #def #[ OPEN_REQ ] (x : 'ch(ReqPacket_t)) : 'ch(chOption ReqPayload_t) {
        K ← get rkeys_loc ;;
        if (x.1 < size K)%N then
          T ← get rsealed_loc ;;
          ret (T x)
        else ret None
      }
    ].

  Definition ReqServerReal : package emptym I_req_server :=
    [package [fmap rkeys_loc ; rnonce_loc] ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ req_key_bits) ;;
        K ← get rkeys_loc ;;
        #put rkeys_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn_t)) : 'ch(chOption ReqSealed_t) {
        K ← get rkeys_loc ;;
        N ← get rnonce_loc ;;
        let n := (q.1, (q.2.1, q.2.2.1)) in
        if (q.1 < size K)%N && sealed_once N n q.2.2.2 then
          #put rnonce_loc := setm N n q.2.2.2 ;;
          ret (Some (seal_req (nth no_req_key K q.1) q.2.1 q.2.2.1 q.2.2.2))
        else ret None
      } ;
      #def #[ SERVE ] (x : 'ch(ReqPacket_t)) : 'ch(chOption ReqAnswer_t) {
        K ← get rkeys_loc ;;
        if (x.1 < size K)%N then
          ret (omap (answer x.1 x.2.1 x.2.2.1)
                 (open_req (nth no_req_key K x.1) x.2.1 x.2.2.1 x.2.2.2))
        else ret None
      }
    ].

  Definition ReqServerHonestOnly : package emptym I_req_server :=
    [package [fmap rkeys_loc ; rnonce_loc ; rsealed_loc] ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        k ← sample uniform (2 ^ req_key_bits) ;;
        K ← get rkeys_loc ;;
        #put rkeys_loc := rcons K k ;;
        ret (size K)
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn_t)) : 'ch(chOption ReqSealed_t) {
        K ← get rkeys_loc ;;
        N ← get rnonce_loc ;;
        let n := (q.1, (q.2.1, q.2.2.1)) in
        if (q.1 < size K)%N && sealed_once N n q.2.2.2 then
          #put rnonce_loc := setm N n q.2.2.2 ;;
          let x := seal_req (nth no_req_key K q.1) q.2.1 q.2.2.1 q.2.2.2 in
          T ← get rsealed_loc ;;
          #put rsealed_loc := setm T (q.1, (q.2.1, (q.2.2.1, x))) q.2.2.2 ;;
          ret (Some x)
        else ret None
      } ;
      #def #[ SERVE ] (x : 'ch(ReqPacket_t)) : 'ch(chOption ReqAnswer_t) {
        K ← get rkeys_loc ;;
        if (x.1 < size K)%N then
          T ← get rsealed_loc ;;
          ret (omap (answer x.1 x.2.1 x.2.2.1) (T x))
        else ret None
      }
    ].

  Definition R_req : package I_req_aead I_req_server :=
    [package emptym ;
      #def #[ NEW_CHAN ] (_ : 'unit) : 'nat {
        #import {sig #[ NEW_CHAN ] : 'unit → 'nat} as new_chan ;;
        i ← new_chan Datatypes.tt ;;
        ret i
      } ;
      #def #[ SEAL_REQ ] (q : 'ch(SealIn_t)) : 'ch(chOption ReqSealed_t) {
        #import {sig #[ SEAL_REQ ] : 'ch(SealIn_t) → 'ch(chOption ReqSealed_t)} as seal ;;
        r ← seal q ;;
        ret r
      } ;
      #def #[ SERVE ] (x : 'ch(ReqPacket_t)) : 'ch(chOption ReqAnswer_t) {
        #import {sig #[ OPEN_REQ ] : 'ch(ReqPacket_t) → 'ch(chOption ReqPayload_t)} as open ;;
        r ← open x ;;
        ret (omap (answer x.1 x.2.1 x.2.2.1) r)
      }
    ].

  Ltac sync_step :=
    ssprove_code_simpl; try (progress cbv zeta);
    first
      [ match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end
      | ssprove_sync_eq => ?
      | ssprove_sync_eq ].

  Ltac close_same :=
    eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].

  Lemma req_server_real_is_reduction : ReqServerReal ≈₀ (R_req ∘ ReqAeadReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma req_server_honest_is_reduction : ReqServerHonestOnly ≈₀ (R_req ∘ ReqAeadIdeal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Theorem request_integrity :
    ∀ LA A,
      ValidPackage LA I_req_server A_export A →
      fseparate LA [fmap rkeys_loc] →
      fseparate LA [fmap rnonce_loc] →
      fseparate LA [fmap rsealed_loc] →
      AdvantageE ReqServerReal ReqServerHonestOnly A
      <= AdvantageE ReqAeadReal ReqAeadIdeal (A ∘ R_req)%pack.
  Proof.
    move=> LA A VA S1 S2 S3.
    ssprove triangle ReqServerReal [::
      (R_req ∘ ReqAeadReal)%pack ;
      (R_req ∘ ReqAeadIdeal)%pack
    ] ReqServerHonestOnly A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE ReqServerReal (R_req ∘ ReqAeadReal)%pack A = 0.
    { apply: req_server_real_is_reduction; solve_fsep. }
    have Z2 : AdvantageE (R_req ∘ ReqAeadIdeal)%pack ReqServerHonestOnly A = 0.
    { rewrite Advantage_sym. apply: req_server_honest_is_reduction; solve_fsep. }
    rewrite Z1 Z2 GRing.add0r GRing.addr0.
    by rewrite -(Advantage_link ReqAeadReal ReqAeadIdeal A R_req).
  Qed.

End RequestIntegrity.
