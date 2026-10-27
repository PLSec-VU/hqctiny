Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum.
Set Warnings "notation-overridden,ambiguous-paths".

From Stdlib Require Import Utf8 Lia.
From extructures Require Import ord fset fmap.

From Equations Require Import Equations.
Require Equations.Prop.DepElim.
Set Equations With UIP.

Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

From SSProve.Crypt Require Import NominalPrelude TotalProbability HybridArgument.
Import PackageNotation.
#[local] Open Scope package_scope.
#[local] Open Scope nat_scope.

Section Hybrid.

  Context (O : ident) (Arg Res : choice_type).
  Context (real ideal : Arg → dist Res).
  Context (O_not_pick : O != PICK).

  #[local] Notation I_O := [interface [ O ] : { Arg ~> Res } ].

  Definition count_loc := mkloc 60 (0 : 'nat).
  Definition slide_loc := mkloc 61 (0 : 'nat).

  Definition INST (b : bool) : game I_O :=
    [package emptym ;
      [ O ] : { Arg ~> Res } (a) {
        if b then real a else ideal a
      }
    ].

  Definition COUNT q : package I_O I_O :=
    [package [fmap count_loc ] ;
      [ O ] : { Arg ~> Res } (a) {
        count ← get count_loc ;;
        #assert count < q ;;
        #put count_loc := count.+1 ;;
        call [ O ] : { Arg ~> Res } a
      }
    ].

  Lemma fhas_pick : fhas (unionm I_O (IPICK nat)) (PICK, ('unit, 'nat)).
  Proof.
    apply: fhas_union_r.
    - by rewrite domm_set domm0 fsetU0 in_fset1 eq_sym.
    - by rewrite /fhas /= setmE eqxx.
  Qed.

  #[local] Hint Extern 1 (fhas (unionm _ (IPICK _)) (mkopsig PICK _ _)) =>
    exact fhas_pick : fmap_solve_db.

  Definition SLIDE q : package (unionm I_O (IPICK nat)) I_O :=
    [package [fmap slide_loc ] ;
      [ O ] : { Arg ~> Res } (a) {
        count ← get slide_loc ;;
        #assert count < q ;;
        #put slide_loc := count.+1 ;;
        i ← call [ PICK ] : { unit ~> nat } tt ;;
        if count < i then
          r ← ideal a ;; ret r
        else if i < count then
          r ← real a ;; ret r
        else
          call [ O ] : { Arg ~> Res } a
      }
    ].

  Definition R (i : 'nat) (c : 'nat) (c' : 'nat) := c = (c' > i)%N.

  Notation inv i := (
    heap_ignore [fmap count_loc ; slide_loc ]
    ⋊ couple_cross count_loc slide_loc eq
    ⋊ couple_rhs count_loc slide_loc (R i)
  ).

  Lemma rsame_head_scheme {A B}
    {m : raw_code A} {f₀ f₁ : A → raw_code B}
    {pre : precond} {post : postcond B B}
    `{Vm : ValidCode emptym [interface] A m} :
    (∀ a : A, ⊢ ⦃ pre ⦄ f₀ a ≈ f₁ a ⦃ post ⦄)
    → ⊢ ⦃ pre ⦄ x ← m ;; f₀ x ≈ x ← m ;; f₁ x ⦃ post ⦄.
  Proof.
    intros. eapply rsame_head_alt; [ exact _ | .. | done ].
    1,2: intros; exfalso; eapply fhas_empty; eassumption.
  Qed.

  Lemma MULTI_SLIDE_perfect q b :
    perfect I_O (COUNT q ∘ INST b)
      (SLIDE q ∘ ((COUNT 1 ∘ INST true) || CONST (if b then 0 else q))).
  Proof.
    ssprove_share.
    eapply prove_perfect.
    apply (eq_rel_perf_ind _ _ (inv (if b then 0 else q))).
    { by ssprove_invariant. }
    simplify_eq_rel a.
    have ON := negbTE O_not_pick.
    have NO : (PICK == O)%B = false by rewrite eq_sym ON.
    rewrite eqxx /=.
    ssprove_code_simpl; simpl.
    rewrite ?eqxx ?ON ?NO /=.
    ssprove_code_simpl; simpl.
    rewrite !code_link_scheme eqxx /=.
    ssprove_code_simpl; simpl.
    apply r_get_remember_lhs => c.
    apply r_get_remember_rhs => cr.
    ssprove_rem_rel 1%N => {cr}<-.
    ssprove_sync => H.
    destruct b; [ destruct c | ]; simpl.
    + ssprove_code_simpl_more.
      ssprove_code_simpl.
      ssprove_code_simpl_more.
      ssprove_swap_rhs 0%N.
      apply r_get_remember_rhs => cr.
      ssprove_rem_rel 0%N.
      rewrite /R /= => -> {cr} /=.
      apply r_put_rhs.
      apply r_put_vs_put.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      { ssprove_invariant. }
      by apply r_ret.
    + apply r_put_vs_put.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      2: by apply r_ret.
      ssprove_invariant.
    + rewrite H.
      apply r_put_vs_put.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      2: by apply r_ret.
      ssprove_invariant.
      rewrite /R 2!ltnNge H (ltnW H) //.
  Qed.

  Notation inv' i := (
    heap_ignore [fmap count_loc ]
    ⋊ couple_lhs count_loc slide_loc (R i%N)
    ⋊ couple_rhs count_loc slide_loc (R i.+1)
  ).

  Lemma SLIDE_succ_perfect q i :
    perfect I_O
      (SLIDE q ∘ ((COUNT 1 ∘ INST false) || CONST i))
      (SLIDE q ∘ ((COUNT 1 ∘ INST true) || CONST i.+1)).
  Proof.
    ssprove_share.
    eapply prove_perfect.
    apply (eq_rel_perf_ind _ _ (inv' i)).
    { by ssprove_invariant. }
    simplify_eq_rel a.
    have ON := negbTE O_not_pick.
    have NO : (PICK == O)%B = false by rewrite eq_sym ON.
    rewrite eqxx /=.
    ssprove_code_simpl; simpl.
    rewrite ?eqxx ?ON ?NO /=.
    ssprove_code_simpl; simpl.
    rewrite !code_link_scheme eqxx /=.
    ssprove_code_simpl; simpl.
    have HS : ProvenBy (syncs slide_loc) (inv' i).
    { by apply: ProvenBy_conj_left. }
    refine (@r_get_vs_get_remember _ _ slide_loc _ _ _ _ HS _) => c.
    ssprove_sync => /ltP H.
    hybrid_cases c i.
    + apply r_put_vs_put.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      { ssprove_invariant; rewrite /R; by replace_many. }
      by apply r_ret.
    + ssprove_code_simpl.
      ssprove_swap_lhs 0%N.
      apply r_get_remember_lhs => c'.
      ssprove_rem_rel 1%N.
      rewrite /= /R ltnn => -> {c'} /=.
      ssprove_code_simpl.
      apply r_put_vs_put.
      apply r_put_lhs.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      { ssprove_invariant; rewrite /R; by replace_many. }
      by apply r_ret.
    + ssprove_code_simpl.
      ssprove_swap_rhs 0%N.
      apply r_get_remember_rhs => c'.
      ssprove_rem_rel 0%N.
      rewrite /= /R ltnn => -> {c'} /=.
      ssprove_code_simpl.
      apply r_put_vs_put.
      apply r_put_rhs.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      { ssprove_invariant; rewrite /R; by replace_many. }
      by apply r_ret.
    + apply r_put_vs_put.
      apply rsame_head_scheme => x.
      ssprove_restore_mem.
      { ssprove_invariant; rewrite /R; by replace_many. }
      by apply r_ret.
  Qed.

  #[local] Open Scope ring_scope.
  #[local] Open Scope sep_scope.

  Definition HYB q := SLIDE q ∘ (ID I_O || RAND (unif q)).

  Theorem multi_instance_hybrid q A `{Adversary I_O A} :
    AdvOf (λ b, COUNT q ∘ INST b) A
    = AdvOf (λ b, COUNT 1 ∘ INST b) (A ∘ HYB q) *+ q.
  Proof.
    rewrite /HYB.
    unshelve refine (@Adv_hybrid I_O I_O q (λ b, COUNT q ∘ INST b) (λ b, COUNT 1 ∘ INST b)
      (SLIDE q) A _ _ _ _ _ _).
    - intro b. ssprove_valid.
    - apply: MULTI_SLIDE_perfect.
    - apply: MULTI_SLIDE_perfect.
    - intros i _. apply: SLIDE_succ_perfect.
  Qed.

  Lemma count_inst_classic q LA A `{VA : ValidPackage LA I_O A_export A} :
    fseparate LA [fmap count_loc] →
    AdvantageE (COUNT q ∘ INST true)%pack (COUNT q ∘ INST false)%pack A
    = Adv (COUNT q ∘ INST true) (COUNT q ∘ INST false) (nom_package_from_valid A).
  Proof.
    move=> SA.
    rewrite -!share_link_sep_link.
    all: try ssprove_separate_solve.
    rewrite Adv_AdvantageE.
    1: reflexivity.
    all: rewrite -fseparate_disj /=.
    all: apply: fseparateUr; [ exact: SA | exact: fseparatem0 ].
  Qed.

  Theorem multi_instance_hybrid_classic q LA A `{VA : ValidPackage LA I_O A_export A} :
    fseparate LA [fmap count_loc] →
    AdvantageE (COUNT q ∘ INST true)%pack (COUNT q ∘ INST false)%pack A
    = AdvOf (λ b, COUNT 1 ∘ INST b) (nom_package_from_valid A ∘ HYB q) *+ q.
  Proof.
    move=> SA.
    rewrite count_inst_classic //.
    exact: multi_instance_hybrid.
  Qed.

  Lemma hyb_classic q LA A `{VA : ValidPackage LA I_O A_export A} :
    fseparate LA [fmap count_loc] →
    fseparate LA [fmap slide_loc] →
    fseparate LA [fmap cell nat] →
    AdvOf (λ b, COUNT 1 ∘ INST b) (nom_package_from_valid A ∘ HYB q)
    = AdvantageE (COUNT 1 ∘ INST true)%pack (COUNT 1 ∘ INST false)%pack
        (A ∘ (SLIDE q ∘ par (ID I_O) (RAND (unif q))))%pack.
  Proof.
    move=> S1 S2 S3.
    rewrite /HYB.
    ssprove_share.
    rewrite Adv_AdvantageE.
    1: reflexivity.
    all: ssprove_separate_solve.
  Qed.

  Definition HYB_raw q : raw_package := (SLIDE q ∘ par (ID I_O) (RAND (unif q)))%pack.

  Theorem multi_to_single_instance q LA A `{VA : ValidPackage LA I_O A_export A} :
    fseparate LA [fmap count_loc] →
    fseparate LA [fmap slide_loc] →
    fseparate LA [fmap cell nat] →
    AdvantageE (COUNT q ∘ INST true)%pack (COUNT q ∘ INST false)%pack A
    = AdvantageE (COUNT 1 ∘ INST true)%pack (COUNT 1 ∘ INST false)%pack (A ∘ HYB_raw q)%pack
      *+ q.
  Proof.
    move=> S1 S2 S3.
    by rewrite multi_instance_hybrid_classic // hyb_classic.
  Qed.

End Hybrid.
