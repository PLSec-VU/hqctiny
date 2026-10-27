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

Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
Notation " 'ch ( x ) " := x (at level 2) : package_scope.

Section CookieIntegrity.

  Context (cookie_key_bits cookie_nonce_bits cookie_bits : nat).
  Context (CookiePlain_t Answer_t : choice_type).

  Definition CookieKey_t := chFin (2 ^ cookie_key_bits).
  Definition Cookie_t := chFin (2 ^ cookie_bits).
  Definition Issued_t := chMap Cookie_t CookiePlain_t.

  Context (seal_cookie : CookieKey_t → CookiePlain_t → 'I_(2 ^ cookie_nonce_bits) → Cookie_t).
  Context (open_cookie : CookieKey_t → Cookie_t → option CookiePlain_t).
  Context (answer : CookiePlain_t → Answer_t).

  Definition key_loc : Location := mkloc 40 (None : 'option CookieKey_t).
  Definition issued_loc : Location := mkloc 41 (emptym : Issued_t).

  Definition ISSUE_COOKIE : ident := 12%N.
  Definition OPEN_COOKIE : ident := 13%N.
  Definition HANDSHAKE : ident := 14%N.
  Definition REQUEST : ident := 15%N.

  Definition I_aead : Interface :=
    [interface
      #val #[ ISSUE_COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t) ;
      #val #[ OPEN_COOKIE ] : 'ch(Cookie_t) → 'ch(chOption CookiePlain_t) ].

  Definition I_server : Interface :=
    [interface
      #val #[ HANDSHAKE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t) ;
      #val #[ REQUEST ] : 'ch(Cookie_t) → 'ch(chOption Answer_t) ].

  Definition CookieAeadReal : package emptym I_aead :=
    [package [fmap key_loc] ;
      #def #[ ISSUE_COOKIE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        ret (seal_cookie ck pt n)
      } ;
      #def #[ OPEN_COOKIE ] (c : 'ch(Cookie_t)) : 'ch(chOption CookiePlain_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        ret (open_cookie ck c)
      }
    ].

  Definition CookieAeadIdeal : package emptym I_aead :=
    [package [fmap key_loc ; issued_loc] ;
      #def #[ ISSUE_COOKIE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        let c := seal_cookie ck pt n in
        T ← get issued_loc ;;
        #put issued_loc := setm T c pt ;;
        ret c
      } ;
      #def #[ OPEN_COOKIE ] (c : 'ch(Cookie_t)) : 'ch(chOption CookiePlain_t) {
        T ← get issued_loc ;;
        ret (T c)
      }
    ].

  Definition ServerReal : package emptym I_server :=
    [package [fmap key_loc] ;
      #def #[ HANDSHAKE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        ret (seal_cookie ck pt n)
      } ;
      #def #[ REQUEST ] (c : 'ch(Cookie_t)) : 'ch(chOption Answer_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        ret (omap answer (open_cookie ck c))
      }
    ].

  Definition ServerIssuedOnly : package emptym I_server :=
    [package [fmap key_loc ; issued_loc] ;
      #def #[ HANDSHAKE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
        kk ← get key_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put key_loc := Some k ;;
                        ret k
              end) ;;
        n ← sample uniform (2 ^ cookie_nonce_bits) ;;
        let c := seal_cookie ck pt n in
        T ← get issued_loc ;;
        #put issued_loc := setm T c pt ;;
        ret c
      } ;
      #def #[ REQUEST ] (c : 'ch(Cookie_t)) : 'ch(chOption Answer_t) {
        T ← get issued_loc ;;
        ret (omap answer (T c))
      }
    ].

  Definition R_server : package I_aead I_server :=
    [package emptym ;
      #def #[ HANDSHAKE ] (pt : 'ch(CookiePlain_t)) : 'ch(Cookie_t) {
        #import {sig #[ ISSUE_COOKIE ] : 'ch(CookiePlain_t) → 'ch(Cookie_t)} as issue ;;
        c ← issue pt ;;
        ret c
      } ;
      #def #[ REQUEST ] (c : 'ch(Cookie_t)) : 'ch(chOption Answer_t) {
        #import {sig #[ OPEN_COOKIE ] : 'ch(Cookie_t) → 'ch(chOption CookiePlain_t)} as open ;;
        r ← open c ;;
        ret (omap answer r)
      }
    ].

  Ltac sync_step :=
    ssprove_code_simpl;
    first
      [ match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            is_var mk; case: mk => [?|] /=
        end
      | ssprove_sync_eq => ?
      | ssprove_sync_eq ].

  Ltac close_same :=
    eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].

  Lemma server_real_is_reduction : ServerReal ≈₀ (R_server ∘ CookieAeadReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: close_same.
  Qed.

  Lemma server_issued_is_reduction : ServerIssuedOnly ≈₀ (R_server ∘ CookieAeadIdeal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: close_same.
  Qed.

  Lemma fseparate_pair (LA : Locations) (l1 l2 : Location) :
    fseparate LA [fmap l1] → fseparate LA [fmap l2] → fseparate LA [fmap l1 ; l2].
  Proof.
    move=> [H1] [H2]; constructor.
    move: H1 H2; rewrite !domm_set !domm0 !fsetU0 => H1 H2.
    by rewrite fdisjointC fdisjointUl !(fdisjointC _ (domm LA)) H1 H2.
  Qed.

  Ltac solve_sep :=
    lazymatch goal with |- fseparate _ _ => idtac end;
    first
      [ assumption
      | exact: fseparate_pair
      | exact: fseparatem0
      | apply: fseparateUr; solve_sep ].

  Theorem cookie_integrity :
    ∀ LA A,
      ValidPackage LA I_server A_export A →
      fseparate LA [fmap key_loc] →
      fseparate LA [fmap issued_loc] →
      AdvantageE ServerReal ServerIssuedOnly A
      <= AdvantageE CookieAeadReal CookieAeadIdeal (A ∘ R_server)%pack.
  Proof.
    move=> LA A VA SK SI.
    ssprove triangle ServerReal [::
      (R_server ∘ CookieAeadReal)%pack ;
      (R_server ∘ CookieAeadIdeal)%pack
    ] ServerIssuedOnly A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE ServerReal (R_server ∘ CookieAeadReal)%pack A = 0.
    { apply: server_real_is_reduction; solve_sep. }
    have Z2 : AdvantageE (R_server ∘ CookieAeadIdeal)%pack ServerIssuedOnly A = 0.
    { rewrite Advantage_sym. apply: server_issued_is_reduction; solve_sep. }
    rewrite Z1 Z2 GRing.add0r GRing.addr0.
    by rewrite -(Advantage_link CookieAeadReal CookieAeadIdeal A R_server).
  Qed.

End CookieIntegrity.
