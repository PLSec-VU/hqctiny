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

Lemma pow2_gt0 (b : nat) : (0 < 2 ^ b)%N.
Proof. by rewrite expn_gt0. Qed.

Definition zero_of_bits (b : nat) : 'I_(2 ^ b) := Ordinal (pow2_gt0 b).

Ltac get_both x :=
  unshelve eapply @r_get_vs_get_remember;
  [ repeat apply: ProvenBy_conj_left; try exact _ | intros x ].

Lemma domm_set_sub {T : ordType} {U V : Type} (S : {fmap T → U}) (C : {fmap T → V}) c u v :
  (∀ x, x \in domm S → x \in domm C) →
  ∀ x, x \in domm (setm S c u) → x \in domm (setm C c v).
Proof.
  move=> H x; rewrite !domm_set !in_fsetU1; case/orP => [/eqP ->|/H ->]; by rewrite ?eqxx ?orbT.
Qed.

Lemma fsep_pair (LA : Locations) (l1 l2 : Location) :
  fseparate LA [fmap l1] → fseparate LA [fmap l2] → fseparate LA [fmap l1 ; l2].
Proof.
  move=> [H1] [H2]; constructor.
  move: H1 H2; rewrite !domm_set !domm0 !fsetU0 => H1 H2.
  by rewrite fdisjointC fdisjointUl !(fdisjointC _ (domm LA)) H1 H2.
Qed.

Lemma fsep_setm (LA M : Locations) (l : Location) :
  fseparate LA [fmap l] → fseparate LA M → fseparate LA (setm M l.1 l.2).
Proof.
  move=> [H1] [H2]; constructor.
  move: H1 H2; rewrite !domm_set domm0 fsetU0 => H1 H2.
  by rewrite fdisjointUr H1 H2.
Qed.

Ltac solve_fsep :=
  lazymatch goal with |- fseparate _ _ => idtac end;
  first
    [ assumption
    | exact: fsep_pair
    | exact: fseparatem0
    | apply: fseparateUr; solve_fsep
    | apply: fsep_setm; [ assumption | solve_fsep ] ].

Section MLKEMCCA.

  Context (mlkem_key_bits mlkem_coin_bits auth_bits : nat).
  Context (McPK_t McCt_t : choice_type).

  Definition MlkemSeed_t := chFin (2 ^ mlkem_key_bits).
  Definition MlkemKey_t := chFin (2 ^ auth_bits).
  Definition Challenge_t := chProd McPK_t (chProd McCt_t MlkemKey_t).

  Context (mlkem_pk : MlkemSeed_t → McPK_t).
  Context (mlkem_encaps : McPK_t → 'I_(2 ^ mlkem_coin_bits) → McCt_t * MlkemKey_t).
  Context (mlkem_decaps : MlkemSeed_t → McCt_t → MlkemKey_t).

  Definition mlkem_seed_loc : Location := mkloc 60 (None : 'option MlkemSeed_t).
  Definition chal_loc : Location := mkloc 63 (emptym : chMap McCt_t MlkemKey_t).
  Definition refuse_loc : Location := mkloc 68 (emptym : chMap McCt_t 'unit).

  Definition CHALLENGE : ident := 64%N.
  Definition DECAPS : ident := 65%N.
  Definition DECAPS_STD : ident := 66%N.

  Definition I_cca : Interface :=
    [interface
      #val #[ CHALLENGE ] : 'unit → 'ch(Challenge_t) ;
      #val #[ DECAPS ] : 'ch(McCt_t) → 'ch(MlkemKey_t) ].

  Definition I_cca_std : Interface :=
    [interface
      #val #[ CHALLENGE ] : 'unit → 'ch(Challenge_t) ;
      #val #[ DECAPS_STD ] : 'ch(McCt_t) → 'ch(chOption MlkemKey_t) ].

  Definition CcaStdReal : package emptym I_cca_std :=
    [package [fmap mlkem_seed_loc ; refuse_loc] ;
      #def #[ CHALLENGE ] (_ : 'unit) : 'ch(Challenge_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        let ck := mlkem_encaps (mlkem_pk sd) r in
        S ← get refuse_loc ;;
        #put refuse_loc := setm S ck.1 Datatypes.tt ;;
        ret (mlkem_pk sd, (ck.1, ck.2))
      } ;
      #def #[ DECAPS_STD ] (c : 'ch(McCt_t)) : 'ch(chOption MlkemKey_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        S ← get refuse_loc ;;
        ret (if c \in domm S then None else Some (mlkem_decaps sd c))
      }
    ].

  Definition CcaStdIdeal : package emptym I_cca_std :=
    [package [fmap mlkem_seed_loc ; refuse_loc] ;
      #def #[ CHALLENGE ] (_ : 'unit) : 'ch(Challenge_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        k' ← sample uniform (2 ^ auth_bits) ;;
        let c := (mlkem_encaps (mlkem_pk sd) r).1 in
        S ← get refuse_loc ;;
        #put refuse_loc := setm S c Datatypes.tt ;;
        ret (mlkem_pk sd, (c, k'))
      } ;
      #def #[ DECAPS_STD ] (c : 'ch(McCt_t)) : 'ch(chOption MlkemKey_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        S ← get refuse_loc ;;
        ret (if c \in domm S then None else Some (mlkem_decaps sd c))
      }
    ].

  Definition CcaReal : package emptym I_cca :=
    [package [fmap mlkem_seed_loc] ;
      #def #[ CHALLENGE ] (_ : 'unit) : 'ch(Challenge_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        let ck := mlkem_encaps (mlkem_pk sd) r in
        ret (mlkem_pk sd, (ck.1, ck.2))
      } ;
      #def #[ DECAPS ] (c : 'ch(McCt_t)) : 'ch(MlkemKey_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        ret (mlkem_decaps sd c)
      }
    ].

  Definition CcaIdeal : package emptym I_cca :=
    [package [fmap mlkem_seed_loc ; chal_loc] ;
      #def #[ CHALLENGE ] (_ : 'unit) : 'ch(Challenge_t) {
        ms ← get mlkem_seed_loc ;;
        sd ← (match ms with
              | Some s => ret s
              | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                        #put mlkem_seed_loc := Some s ;;
                        ret s
              end) ;;
        r ← sample uniform (2 ^ mlkem_coin_bits) ;;
        k' ← sample uniform (2 ^ auth_bits) ;;
        let c := (mlkem_encaps (mlkem_pk sd) r).1 in
        C ← get chal_loc ;;
        #put chal_loc := setm C c k' ;;
        ret (mlkem_pk sd, (c, k'))
      } ;
      #def #[ DECAPS ] (c : 'ch(McCt_t)) : 'ch(MlkemKey_t) {
        C ← get chal_loc ;;
        match C c with
        | Some k => ret k
        | None =>
            ms ← get mlkem_seed_loc ;;
            sd ← (match ms with
                  | Some s => ret s
                  | None => s ← sample uniform (2 ^ mlkem_key_bits) ;;
                            #put mlkem_seed_loc := Some s ;;
                            ret s
                  end) ;;
            ret (mlkem_decaps sd c)
        end
      }
    ].

  Definition R_std : package I_cca_std I_cca :=
    [package [fmap chal_loc] ;
      #def #[ CHALLENGE ] (_ : 'unit) : 'ch(Challenge_t) {
        #import {sig #[ CHALLENGE ] : 'unit → 'ch(Challenge_t)} as challenge ;;
        x ← challenge Datatypes.tt ;;
        C ← get chal_loc ;;
        #put chal_loc := setm C x.2.1 x.2.2 ;;
        ret x
      } ;
      #def #[ DECAPS ] (c : 'ch(McCt_t)) : 'ch(MlkemKey_t) {
        #import {sig #[ DECAPS_STD ] : 'ch(McCt_t) → 'ch(chOption MlkemKey_t)} as decaps ;;
        C ← get chal_loc ;;
        match C c with
        | Some k => ret k
        | None =>
            r ← decaps c ;;
            ret (odflt (zero_of_bits auth_bits) r)
        end
      }
    ].

Lemma cca_ideal_is_std_reduction : CcaIdeal ≈₀ (R_std ∘ CcaStdIdeal)%pack.
Proof.
  eapply eq_rel_perf_ind with
    (heap_ignore [fmap refuse_loc] ⋊
     couple_rhs refuse_loc chal_loc (λ (S : chMap McCt_t 'unit) (C : chMap McCt_t MlkemKey_t), ∀ c, c \in domm S → c \in domm C)).
  { ssprove_invariant => //. }
  simplify_eq_rel x.
  all: simplify_linking.
  all: ssprove_code_simpl.
  - get_both ms.
    case: ms => [s|] /=.
    + ssprove_sync => r. ssprove_sync => k'.
      apply: r_get_remember_rhs => S.
      ssprove_swap_rhs 0%N.
      get_both C.
      ssprove_rem_rel 0%N => Hinv.
      apply: r_put_rhs.
      apply: r_put_vs_put.
      ssprove_restore_mem.
      * ssprove_invariant. exact: domm_set_sub.
      * by apply: r_ret.
    + ssprove_forget_all. ssprove_sync => s. ssprove_sync. 1: ssprove_invariant. ssprove_sync => r. ssprove_sync => k'.
      apply: r_get_remember_rhs => S.
      ssprove_swap_rhs 0%N.
      get_both C.
      ssprove_rem_rel 0%N => Hinv.
      apply: r_put_rhs.
      apply: r_put_vs_put.
      ssprove_restore_mem.
      * ssprove_invariant. exact: domm_set_sub.
      * by apply: r_ret.
  - get_both C.
    case HC: (C x) => [k|] /=.
    + ssprove_forget_all. by apply: r_ret.
    + get_both ms.
      case: ms => [s|] /=.
      * apply: r_get_remember_rhs => S.
        ssprove_rem_rel 0%N => Hinv.
        have Hx : x \in domm S = false.
        { apply/negP => /Hinv; by rewrite mem_domm HC. }
        rewrite Hx /=.
        ssprove_forget_all. by apply: r_ret.
      * do 2 ssprove_forget. ssprove_sync => s. ssprove_sync. 1: ssprove_invariant.
        apply: r_get_remember_rhs => S.
        ssprove_rem_rel 0%N => Hinv.
        have Hx : x \in domm S = false.
        { apply/negP => /Hinv; by rewrite mem_domm HC. }
        rewrite Hx /=.
        ssprove_forget_all. by apply: r_ret.
Qed.

Context (mlkem_correct : ∀ s r,
  mlkem_decaps s (mlkem_encaps (mlkem_pk s) r).1 = (mlkem_encaps (mlkem_pk s) r).2).

Definition chal_sound (ms : 'option MlkemSeed_t) (C : chMap McCt_t MlkemKey_t) : Prop :=
  ∀ c k, C c = Some k → ∃ s, ms = Some s ∧ mlkem_decaps s c = k.

Lemma chal_sound_none_empty C c : chal_sound None C → C c = None.
Proof. move=> H; case E: (C c) => [k|] //; by case: (H _ _ E) => ? []. Qed.

Lemma chal_sound_set s C c k :
  chal_sound (Some s) C → mlkem_decaps s c = k → chal_sound (Some s) (setm C c k).
Proof.
  move=> H Hk c' k'; rewrite setmE.
  case: eqP => [-> [<-]|_ /H //]; by exists s.
Qed.

Lemma cca_real_is_std_reduction : CcaReal ≈₀ (R_std ∘ CcaStdReal)%pack.
Proof.
  eapply eq_rel_perf_ind with
    (heap_ignore [fmap refuse_loc ; chal_loc] ⋊
     couple_rhs refuse_loc chal_loc (λ (S : chMap McCt_t 'unit) (C : chMap McCt_t MlkemKey_t), ∀ c, c \in domm S → c \in domm C) ⋊
     couple_cross mlkem_seed_loc chal_loc chal_sound).
  { ssprove_invariant => //. }
  simplify_eq_rel x.
  all: simplify_linking.
  all: ssprove_code_simpl.
  - get_both ms.
    case: ms => [s|] /=.
    + ssprove_sync => r.
      apply: r_get_remember_rhs => S.
      ssprove_swap_rhs 0%N.
      apply: r_get_remember_rhs => C.
      ssprove_rem_rel 0%N => Hsound.
      ssprove_rem_rel 1%N => Hsub.
      apply: r_put_rhs.
      apply: r_put_rhs.
      ssprove_restore_mem.
      * ssprove_invariant.
        -- exact: domm_set_sub.
        -- move=> H; apply: chal_sound_set H _; exact: mlkem_correct.
      * by apply: r_ret.
    + ssprove_swap_seq_rhs [:: 4 ; 3 ; 2 ; 1 ; 0 ]%N.
      apply: r_get_remember_rhs => C.
      ssprove_swap_seq_rhs [:: 2 ; 1 ; 0 ]%N.
      apply: r_get_remember_rhs => S.
      ssprove_rem_rel 0%N => Hsound.
      ssprove_rem_rel 1%N => Hsub.
      ssprove_sync => s.
      apply: r_put_vs_put.
      ssprove_sync => r.
      apply: r_put_rhs.
      apply: r_put_rhs.
      ssprove_restore_mem.
      * ssprove_invariant.
        -- exact: domm_set_sub.
        -- move=> H; apply: chal_sound_set; last exact: mlkem_correct.
           move=> c k; by rewrite (chal_sound_none_empty _ c H).
      * by apply: r_ret.
  - apply: r_get_remember_rhs => C.
    case HC: (C x) => [k|] /=.
    + apply: r_get_remember_lhs => ms.
      ssprove_rem_rel 0%N => Hsound.
      case: (Hsound _ _ HC) => s [Hms Hk].
      rewrite Hms /= Hk.
      ssprove_forget_all.
      by apply: r_ret.
    + get_both ms.
      case: ms => [s|] /=.
      * apply: r_get_remember_rhs => S.
        ssprove_rem_rel 1%N => Hsub.
        have Hx : x \in domm S = false.
        { apply/negP => /Hsub; by rewrite mem_domm HC. }
        rewrite Hx /=.
        ssprove_forget_all.
        by apply: r_ret.
      * ssprove_swap_seq_rhs [:: 1 ; 0 ]%N.
        apply: r_get_remember_rhs => S.
        ssprove_rem_rel 0%N => Hsound.
        ssprove_rem_rel 1%N => Hsub.
        have Hx : x \in domm S = false.
        { apply/negP => /Hsub; by rewrite mem_domm HC. }
        rewrite Hx /=.
        ssprove_sync => s.
        apply: r_put_vs_put.
        ssprove_restore_mem.
        -- ssprove_invariant.
           move=> H c k.
           by rewrite (chal_sound_none_empty _ c H).
        -- by apply: r_ret.
Qed.

Theorem cca_from_standard :
  ∀ LA A,
    ValidPackage LA I_cca A_export A →
    fseparate LA [fmap mlkem_seed_loc] →
    fseparate LA [fmap chal_loc] →
    fseparate LA [fmap refuse_loc] →
    AdvantageE CcaReal CcaIdeal A
    <= AdvantageE CcaStdReal CcaStdIdeal (A ∘ R_std)%pack.
Proof.
  move=> LA A VA S1 S2 S3.
  ssprove triangle CcaReal [::
    (R_std ∘ CcaStdReal)%pack ;
    (R_std ∘ CcaStdIdeal)%pack
  ] CcaIdeal A as ineq.
  eapply Order.POrderTheory.le_trans; first exact: ineq.
  have Z1 : AdvantageE CcaReal (R_std ∘ CcaStdReal)%pack A = 0.
  { apply: cca_real_is_std_reduction; solve_fsep. }
  have Z2 : AdvantageE (R_std ∘ CcaStdIdeal)%pack CcaIdeal A = 0.
  { rewrite Advantage_sym. apply: cca_ideal_is_std_reduction; solve_fsep. }
  rewrite Z1 Z2 GRing.add0r GRing.addr0.
  by rewrite -(Advantage_link CcaStdReal CcaStdIdeal A R_std).
Qed.

End MLKEMCCA.
