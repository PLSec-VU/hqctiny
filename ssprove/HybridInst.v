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


Section HybridInst.

  Context (St Arg Res : choice_type) (q : nat).
  Context (new : bool → dist St).
  Context (query : bool → St → Arg → dist (chProd St Res)).
  Context (absent : Arg → Res).

  Definition imap_loc : Location := mkloc 130 (emptym : chMap 'nat St).
  Definition icount_loc : Location := mkloc 131 (0%N : 'nat).
  Definition single_loc : Location := mkloc 132 (None : 'option St).
  Definition hmap_loc : Location := mkloc 133 (emptym : chMap 'nat St).
  Definition hcount_loc : Location := mkloc 134 (0%N : 'nat).

  Definition NEWI : ident := 135%N.
  Definition QUERYI : ident := 136%N.
  Definition NEW1 : ident := 137%N.
  Definition QUERY1 : ident := 138%N.

  Definition I_multi : Interface :=
    [interface
      #val #[ NEWI ] : 'unit → 'nat ;
      #val #[ QUERYI ] : 'ch(chProd 'nat Arg) → 'ch(Res) ].

  Definition I_single : Interface :=
    [interface
      #val #[ NEW1 ] : 'unit → 'unit ;
      #val #[ QUERY1 ] : 'ch(Arg) → 'ch(Res) ].


  Definition MULTI (b : bool) : package emptym I_multi :=
    [package [fmap imap_loc ; icount_loc] ;
      #def #[ NEWI ] (_ : 'unit) : 'nat {
        c ← get icount_loc ;;
        M ← get imap_loc ;;
        if (c < q)%N then
          s ← new b ;;
          #put imap_loc := setm M c s ;;
          #put icount_loc := c.+1 ;;
          ret c
        else ret c
      } ;
      #def #[ QUERYI ] (x : 'ch(chProd 'nat Arg)) : 'ch(Res) {
        M ← get imap_loc ;;
        match M x.1 with
        | None => ret (absent x.2)
        | Some s =>
            p ← query b s x.2 ;;
            #put imap_loc := setm M x.1 p.1 ;;
            ret p.2
        end
      }
    ].

  Definition SINGLE (b : bool) : package emptym I_single :=
    [package [fmap single_loc] ;
      #def #[ NEW1 ] (_ : 'unit) : 'unit {
        st ← get single_loc ;;
        match st with
        | Some _ => ret Datatypes.tt
        | None =>
            s ← new b ;;
            #put single_loc := Some s ;;
            ret Datatypes.tt
        end
      } ;
      #def #[ QUERY1 ] (a : 'ch(Arg)) : 'ch(Res) {
        st ← get single_loc ;;
        match st with
        | None => ret (absent a)
        | Some s =>
            p ← query b s a ;;
            #put single_loc := Some p.1 ;;
            ret p.2
        end
      }
    ].


  Definition HYB (j : nat) : package I_single I_multi :=
    [package [fmap hmap_loc ; hcount_loc] ;
      #def #[ NEWI ] (_ : 'unit) : 'nat {
        #import {sig #[ NEW1 ] : 'unit → 'unit} as new1 ;;
        c ← get hcount_loc ;;
        M ← get hmap_loc ;;
        if (c < q)%N then
          if (c == j)%B then
            _ ← new1 Datatypes.tt ;;
            #put hcount_loc := c.+1 ;;
            ret c
          else
            s ← new (j < c)%N ;;
            #put hmap_loc := setm M c s ;;
            #put hcount_loc := c.+1 ;;
            ret c
        else ret c
      } ;
      #def #[ QUERYI ] (x : 'ch(chProd 'nat Arg)) : 'ch(Res) {
        #import {sig #[ QUERY1 ] : 'ch(Arg) → 'ch(Res)} as query1 ;;
        M ← get hmap_loc ;;
        if (x.1 == j)%B then
          r ← query1 x.2 ;;
          ret r
        else
          match M x.1 with
          | None => ret (absent x.2)
          | Some s =>
              p ← query (j < x.1)%N s x.2 ;;
              #put hmap_loc := setm M x.1 p.1 ;;
              ret p.2
          end
      }
    ].


  Definition view (j : nat) (H : chMap 'nat St) (S : 'option St) (i : nat) : option St :=
    if (i == j)%B then S else H i.

  Lemma code_link_dist {A : choiceType} (m : dist A) p : code_link m p = m.
  Proof. exact: (code_link_scheme _ _ _ _ (prog_valid m)). Qed.

  Lemma rsame_head_dist {A B : choiceType} (m : dist A) (f₀ f₁ : A → raw_code B)
    (pre : precond) (post : postcond B B) :
    (∀ a : A, ⊢ ⦃ pre ⦄ f₀ a ≈ f₁ a ⦃ post ⦄) →
    ⊢ ⦃ pre ⦄ x ← m ;; f₀ x ≈ x ← m ;; f₁ x ⦃ post ⦄.
  Proof.
    intros. eapply rsame_head_alt; [ exact (prog_valid m) | .. | done ].
    1,2: intros; exfalso; eapply fhas_empty; eassumption.
  Qed.

  Definition multi_fresh (c : 'nat) (M : chMap 'nat St) : Prop :=
    (c <= q)%N ∧ ∀ i, (c <= i)%N → M i = None.

  Definition multi_view (j : nat) (M H : chMap 'nat St) (S : 'option St) : Prop :=
    ∀ i, M i = view j H S i.

  Definition multi_bounded (M : chMap 'nat St) : Prop :=
    ∀ i s, M i = Some s → (i < q)%N.

  Lemma multi_bounded_new (M : chMap 'nat St) (c : nat) (s : St) : (c < q)%N → multi_bounded M → multi_bounded (setm M c s).
  Proof.
    move=> Hc H i s'; rewrite setmE; case E: (i == c)%B => Hs.
    - by move/eqP: E => ->.
    - exact: H Hs.
  Qed.

  Lemma multi_bounded_upd (M : chMap 'nat St) (i : nat) (s s' : St) : M i = Some s' → multi_bounded M → multi_bounded (setm M i s).
  Proof.
    move=> Hi H i' s''; rewrite setmE; case E: (i' == i)%B => Hs.
    - move/eqP: E => ->; exact: H Hi.
    - exact: H Hs.
  Qed.

  Definition multi_others (j : nat) (M H : chMap 'nat St) : Prop :=
    ∀ i, (i != j)%B → M i = H i.

  Lemma multi_others_set_j j M H x s :
    (x == j)%B → multi_others j M H → multi_others j (setm M x s) H.
  Proof.
    move=> /eqP -> Hv i Hi; rewrite setmE.
    case E: (i == j)%B; first by rewrite E in Hi.
    exact: Hv.
  Qed.

  Lemma multi_others_set_both j M H x s :
    multi_others j M H → multi_others j (setm M x s) (setm H x s).
  Proof. move=> Hv i Hi; rewrite !setmE; case: (i == x)%B => //; exact: Hv. Qed.

  Lemma single_set_j (j : nat) (M : chMap 'nat St) x s (S : 'option St) :
    (x == j)%B → M j = S → setm M x s j = Some s.
  Proof. move=> /eqP -> _; by rewrite setmE eqxx. Qed.

  Lemma single_set_other (j : nat) (M : chMap 'nat St) x s (S : 'option St) :
    (x == j)%B = false → M j = S → setm M x s j = S.
  Proof. move=> Hx HS; rewrite setmE eq_sym Hx; exact: HS. Qed.

  Notation inv_mh j :=
    (heap_ignore [fmap imap_loc ; icount_loc ; hmap_loc ; hcount_loc ; single_loc] ⋊
     couple_cross icount_loc hcount_loc eq ⋊
     couple_cross imap_loc hmap_loc (multi_others j) ⋊
     couple_cross imap_loc single_loc (λ (M : chMap 'nat St) (S : 'option St), M j = S) ⋊
     couple_lhs icount_loc imap_loc multi_fresh ⋊
     rel_app [:: (lhs, imap_loc)] multi_bounded).

  Lemma multi_fresh_new c M s :
    (c < q)%N → multi_fresh c M → multi_fresh c.+1 (setm M c s).
  Proof.
    move=> Hc [_ H]; split => // i Hi; rewrite setmE.
    case: eqP => [E|_]; first by rewrite E ltnn in Hi.
    by apply: H; apply: ltnW.
  Qed.

  Lemma multi_fresh_upd c M i s s' :
    multi_fresh c M → M i = Some s' → multi_fresh c (setm M i s).
  Proof.
    move=> [Hq H] Hi; split => // i' Hi'; rewrite setmE.
    case: eqP => [E|_]; last exact: H.
    subst; by rewrite H in Hi.
  Qed.

  Lemma multi_fresh_lt c M i s : multi_fresh c M → M i = Some s → (i < c)%N.
  Proof. move=> [_ H] Hi; rewrite ltnNge; apply/negP => /H; by rewrite Hi. Qed.

  Lemma multi_view_set_single j M H S i s :
    (i == j)%B → multi_view j M H S → multi_view j (setm M i s) H (Some s).
  Proof.
    move=> /eqP Ei Hv i'; subst i; rewrite setmE /view.
    case E: (i' == j)%B => //; move: (Hv i'); by rewrite /view E.
  Qed.

  Lemma multi_view_set_map j M H S i s :
    (i == j)%B = false → multi_view j M H S → multi_view j (setm M i s) (setm H i s) S.
  Proof.
    move=> Hij Hv i'; rewrite /view !setmE.
    case Ei: (i' == i)%B; case Ej: (i' == j)%B => //=.
    all: first
      [ move/eqP: Ei => Ei; move/eqP: Ej => Ej; subst; by rewrite eqxx in Hij
      | move: (Hv i'); by rewrite /view Ej ].
  Qed.

  Ltac rem_all_l := repeat (apply: r_get_remember_lhs => ?).

  Lemma multi_is_hyb b b' j :
    (∀ c, (c < q)%N → (c == j)%B = false → (j < c)%N = b) →
    ((j < q)%N → b' = b) →
    MULTI b ≈₀ (HYB j ∘ SINGLE b')%pack.
  Proof.
    move=> Hb Hb'.
    eapply eq_rel_perf_ind with (inv_mh j).
    { ssprove_invariant.
      all: rewrite /rel_empty /heap_init /=.
      all: try done.
      all: try (move=> i _; by rewrite !emptymE).
      all: try (split => // i _; by rewrite emptymE).
      all: try (move=> i s; by rewrite emptymE). }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_lhs => M.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => H.
      ssprove_rem_rel 4%N => Ec. subst c'.
      ssprove_rem_rel 1%N => Hf.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      case Hcj: (c == j)%B => /=.
      + apply: r_get_remember_rhs => S.
        ssprove_rem_rel 2%N => Hv.
        have HS : S = None.
        { rewrite -Hv; move/eqP: Hcj => <-. apply: Hf.2; exact: leqnn. }
        rewrite HS /=. ssprove_code_simpl.
        have Ejq : (j < q)%N by move/eqP: Hcj => <-.
        rewrite (Hb' Ejq) ?code_link_dist.
        apply: rsame_head_dist => s.
        apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> Hx; first [ exact: (multi_fresh_new _ _ _ Hcq Hx)
                                | exact: (multi_bounded_new _ _ _ Hcq Hx)
                                | exact: (multi_others_set_j _ _ _ _ _ Hcj Hx)
                                | exact: (single_set_j _ _ _ _ _ Hcj Hx) ].
        * by apply: r_ret.
      + rewrite (Hb _ Hcq Hcj).
        rewrite ?code_link_dist.
        apply: rsame_head_dist => s.
        apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> Hx; first [ exact: (multi_fresh_new _ _ _ Hcq Hx)
                                | exact: (multi_bounded_new _ _ _ Hcq Hx)
                                | exact: (multi_others_set_both _ _ _ _ _ Hx)
                                | exact: (single_set_other _ _ _ _ _ Hcj Hx) ].
        * by apply: r_ret.
    - apply: r_get_remember_lhs => M.
      apply: r_get_remember_rhs => H.
      case Hij: (x.1 == j)%B => /=.
      + apply: r_get_remember_rhs => S.
        ssprove_rem_rel 2%N => Hv.
        have HM : M x.1 = S by move/eqP: Hij => ->.
        rewrite HM.
        case HS: S => [s|] /=; last first.
        { ssprove_forget_all. by apply: r_ret. }
        rewrite HS in HM.
        ssprove_rem_rel 0%N => Hbd.
        have Ejq : (j < q)%N by move/eqP: Hij => <-; exact: Hbd _ _ HM.
        rewrite (Hb' Ejq) ?code_link_dist.
        apply: rsame_head_dist => p.
        apply: r_put_lhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> Hx; first [ exact: (multi_fresh_upd _ _ _ _ _ Hx HM)
                                | exact: (multi_bounded_upd _ _ _ _ HM Hx)
                                | exact: (multi_others_set_j _ _ _ _ _ Hij Hx)
                                | exact: (single_set_j _ _ _ _ _ Hij Hx) ].
        * by apply: r_ret.
      + ssprove_rem_rel 3%N => Hv.
        have HM : M x.1 = H x.1 by apply: Hv; rewrite Hij.
        rewrite HM.
        case HH: (H x.1) => [s|] /=; last first.
        { ssprove_forget_all. by apply: r_ret. }
        rewrite -HM in HH.
        ssprove_rem_rel 0%N => Hbd.
        have Hiq : (x.1 < q)%N := Hbd _ _ HH.
        rewrite (Hb _ Hiq Hij) ?code_link_dist.
        apply: rsame_head_dist => p.
        apply: r_put_lhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: move=> Hx; first [ exact: (multi_fresh_upd _ _ _ _ _ Hx HH)
                                | exact: (multi_bounded_upd _ _ _ _ HH Hx)
                                | exact: (multi_others_set_both _ _ _ _ _ Hx)
                                | exact: (single_set_other _ _ _ _ _ Hij Hx) ].
        * by apply: r_ret.
  Qed.


  Notation inv_step j :=
    (heap_ignore [fmap hmap_loc ; hcount_loc ; single_loc] ⋊
     couple_cross hcount_loc hcount_loc eq ⋊
     rel_app [:: (lhs, single_loc) ; (rhs, hmap_loc)]
       (λ (SL : 'option St) (HR : chMap 'nat St), SL = HR j) ⋊
     rel_app [:: (lhs, hmap_loc) ; (rhs, single_loc)]
       (λ (HL : chMap 'nat St) (SR : 'option St), HL j.+1 = SR) ⋊
     rel_app [:: (lhs, hmap_loc) ; (rhs, hmap_loc)]
       (λ (HL HR : chMap 'nat St), ∀ i, (i != j)%B → (i != j.+1)%B → HL i = HR i) ⋊
     rel_app [:: (lhs, hcount_loc) ; (lhs, hmap_loc)]
       (λ (c : 'nat) (HL : chMap 'nat St), ∀ i, (c <= i)%N → (i != j)%B → HL i = None) ⋊
     rel_app [:: (lhs, hcount_loc) ; (lhs, single_loc)]
       (λ (c : 'nat) (SL : 'option St), (c <= j)%N → SL = None)).

  Ltac map_case :=
    repeat match goal with
      | |- context [ setm _ ?k _ ?i ] => rewrite (setmE _ k _ i)
      end.

  Ltac contra_eq :=
    match goal with
    | E : is_true (_ == _)%B |- _ => move/eqP: E => E; subst; contra_eq
    | E : (_ == _)%B = true |- _ => move/eqP: E => E; subst; contra_eq
    | _ => by repeat match goal with
                     | H : _ |- _ => rewrite ?eqxx ?ltnn ?ltnSn in H
                     end
    end.

  Ltac step_close :=
    first
      [ by rewrite ltnn
      | by move=> *; rewrite setmE eqxx
      | by move=> *; rewrite setmE eqxx
      | let H := fresh "H" in let i := fresh "i" in
        let Hi := fresh "Hi" in let Hi1 := fresh "Hi1" in let E := fresh "E" in
        move=> H i Hi Hi1; rewrite setmE; case E: (i == _)%B;
        [ move/eqP: E => E; subst; by rewrite ?eqxx in Hi Hi1 | exact: H ]
      | let H := fresh "H" in let i := fresh "i" in
        let Hi := fresh "Hi" in let Hi1 := fresh "Hi1" in let E := fresh "E" in
        move=> H i Hi Hi1; rewrite setmE; case E: (i == _)%B;
        [ move/eqP: E => E; subst | apply: H => //; exact: ltnW ];
        first [ by rewrite ltnn in Hi | by rewrite ltnNge leqnSn in Hi
              | by match goal with
                   | HS : _ = Some _ |- _ => rewrite H in HS
                   end ]
      | let H := fresh "H" in let Hc := fresh "Hc" in
        move=> H Hc; first [ by have := H Hc | apply: H; exact: ltnW ]
      | let H := fresh "H" in let E := fresh "E" in
        move=> H; rewrite setmE; case E: (_ == _)%B; [ contra_eq | exact: H ]
      | let H := fresh "H" in let i := fresh "i" in let Hi := fresh "Hi" in
        let Hi1 := fresh "Hi1" in let E := fresh "E" in
        move=> H i Hi Hi1; rewrite !setmE; case E: (i == _)%B; [ done | exact: H ] ].

  Lemma hyb_step j :
    (HYB j ∘ SINGLE false)%pack ≈₀ (HYB j.+1 ∘ SINGLE true)%pack.
  Proof.
    eapply eq_rel_perf_ind with (inv_step j).
    { ssprove_invariant.
      all: rewrite /rel_empty /=.
      all: try done.
      all: intros; by rewrite emptymE. }
    simplify_eq_rel x.
    all: simplify_linking.
    all: ssprove_code_simpl.
    - apply: r_get_remember_lhs => c.
      apply: r_get_remember_lhs => HL.
      apply: r_get_remember_rhs => c'.
      apply: r_get_remember_rhs => HR.
      ssprove_rem_rel 5%N => Ec. subst c'.
      cbv zeta.
      case Hcq: (c < q)%N => /=; last first.
      { ssprove_forget_all. by apply: r_ret. }
      case Hcj: (c == j)%B => /=.
      + move/eqP: Hcj => Hcj. subst c.
        rewrite (ltn_eqF (ltnSn j)) /=.
        apply: r_get_remember_lhs => SL.
        ssprove_rem_rel 0%N => H3'.
        rewrite (H3' (leqnn j)) /=.
        have -> : (j.+1 < j)%N = false by rewrite ltnNge leqnSn.
        rewrite ?code_link_dist.
        apply: rsame_head_dist => s.
        apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          all: step_close.
        * by apply: r_ret.
      + case Hcj1: (c == j.+1)%B => /=.
        * move/eqP: Hcj1 => Hcj1. subst c.
          apply: r_get_remember_rhs => SR.
          ssprove_rem_rel 3%N => H2b.
          ssprove_rem_rel 1%N => H3.
          have HSR : SR = None.
          { rewrite -H2b; apply: H3 => //. by rewrite eq_sym (ltn_eqF (ltnSn j)). }
          rewrite HSR /= ltnSn ?code_link_dist.
          apply: rsame_head_dist => s.
          apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             ++ by move=> *; rewrite setmE eqxx.
             ++ move=> H i Hi Hi1; rewrite setmE; case E: (i == j.+1)%B; [ by rewrite E in Hi1 | exact: H ].
             ++ move=> H i Hi Hne; rewrite setmE; case E: (i == j.+1)%B;
                  [ move/eqP: E => E; subst; by rewrite ltnn in Hi | apply: H => //; exact: ltnW ].
          -- by apply: r_ret.
        * have -> : (j.+1 < c)%N = (j < c)%N by rewrite ltn_neqAle eq_sym Hcj1.
          rewrite ?code_link_dist.
          apply: rsame_head_dist => s.
          apply: r_put_lhs. apply: r_put_lhs. apply: r_put_rhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             ++ move=> ->; rewrite setmE; case E: (j == c)%B => //.
                move/eqP: E => E; subst; by rewrite eqxx in Hcj.
             ++ move=> <-; rewrite setmE; case E: (j.+1 == c)%B => //.
                move/eqP: E => E; subst; by rewrite eqxx in Hcj1.
             ++ move=> H i Hi Hi1; rewrite !setmE; case E: (i == c)%B => //; exact: H.
             ++ move=> H i Hi Hne; rewrite setmE; case E: (i == c)%B;
                  [ move/eqP: E => E; subst; by rewrite ltnn in Hi | apply: H => //; exact: ltnW ].
          -- by apply: r_ret.
    - apply: r_get_remember_lhs => HL.
      apply: r_get_remember_rhs => HR.
      cbv zeta.
      case Hij: (x.1 == j)%B => /=.
      + move/eqP: Hij => Hij.
        have Hij1 : (x.1 == j.+1)%B = false by rewrite Hij (ltn_eqF (ltnSn j)).
        rewrite Hij1 /=.
        apply: r_get_remember_lhs => SL.
        ssprove_rem_rel 4%N => H2a.
        rewrite H2a Hij.
        case HS: (HR j) => [s|] /=; last first.
        { ssprove_forget_all. by apply: r_ret. }
        have -> : (j.+1 < j)%N = false by rewrite ltnNge leqnSn.
        rewrite ?code_link_dist.
        apply: rsame_head_dist => p.
        apply: r_put_lhs. apply: r_put_rhs.
        ssprove_restore_mem.
        * ssprove_invariant.
          -- by move=> _; rewrite setmE eqxx.
          -- move=> H i Hi Hi1; rewrite setmE; case E: (i == j)%B; [ by rewrite E in Hi | exact: H ].
          -- by move=> H Hc; have := H Hc.
        * by apply: r_ret.
      + case Hij1: (x.1 == j.+1)%B => /=.
        * move/eqP: Hij1 => Hij1.
          apply: r_get_remember_rhs => SR.
          ssprove_rem_rel 3%N => H2b.
          rewrite Hij1 H2b.
          case HS: SR => [s|] /=; last first.
          { ssprove_forget_all. by apply: r_ret. }
          rewrite ltnSn ?code_link_dist.
          apply: rsame_head_dist => p.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             ++ by move=> _; rewrite setmE eqxx.
             ++ move=> H i Hi Hi1; rewrite setmE; case E: (i == j.+1)%B;
                  [ by rewrite E in Hi1 | exact: H ].
             ++ move=> H i Hv Hne; rewrite setmE; case E: (i == j.+1)%B; last exact: H.
                move/eqP: E => E; subst i; have := H _ Hv Hne; by rewrite H2b HS.
          -- by apply: r_ret.
        * ssprove_rem_rel 2%N => H2c.
          have Hn : (x.1 != j)%B by rewrite Hij.
          have Hn1 : (x.1 != j.+1)%B by rewrite Hij1.
          rewrite (H2c _ Hn Hn1).
          case HS: (HR x.1) => [s|] /=; last first.
          { ssprove_forget_all. by apply: r_ret. }
          have -> : (j.+1 < x.1)%N = (j < x.1)%N by rewrite ltn_neqAle eq_sym Hij1.
          rewrite ?code_link_dist.
          apply: rsame_head_dist => p.
          apply: r_put_lhs. apply: r_put_rhs.
          ssprove_restore_mem.
          -- ssprove_invariant.
             ++ move=> ->; rewrite setmE; case E: (j == x.1)%B => //.
                move/eqP: E => E; by rewrite -E eqxx in Hij.
             ++ move=> <-; rewrite setmE; case E: (j.+1 == x.1)%B => //.
                move/eqP: E => E; by rewrite -E eqxx in Hij1.
             ++ move=> H i Hi Hi1; rewrite !setmE; case: (i == x.1)%B => //; exact: H.
             ++ move=> H i Hv Hne; rewrite setmE; case E: (i == x.1)%B; last exact: H.
                move/eqP: E => E; subst i; have := H _ Hv Hne; by rewrite (H2c _ Hn Hn1) HS.
          -- by apply: r_ret.
  Qed.


  Lemma AdvantageE_refl (G : raw_package) A : AdvantageE G G A = 0.
  Proof. by rewrite /AdvantageE subrr Num.Theory.normr0. Qed.

  Section Telescope.

    Context (LA : Locations) (A : raw_package).
    Context (VA : ValidPackage LA I_multi A_export A).
    Context (S1 : fseparate LA [fmap imap_loc ; icount_loc]).
    Context (S2 : fseparate LA [fmap hmap_loc ; hcount_loc]).
    Context (S3 : fseparate LA [fmap single_loc]).

    Lemma hybrid_prefix k :
      AdvantageE (HYB 0 ∘ SINGLE true)%pack (HYB k ∘ SINGLE true)%pack A
      <= \sum_(j < k) AdvantageE (SINGLE true) (SINGLE false) (A ∘ HYB j)%pack.
    Proof.
      elim: k => [|k IH].
      - by rewrite AdvantageE_refl big_ord0.
      - rewrite big_ord_recr /=.
        eapply Order.POrderTheory.le_trans; first exact: (Advantage_triangle _ _ (HYB k ∘ SINGLE false)%pack).
        eapply Order.POrderTheory.le_trans.
        { apply: Num.Theory.lerD; first exact: (Advantage_triangle _ _ (HYB k ∘ SINGLE true)%pack).
          exact: Order.POrderTheory.le_refl. }
        have Z : AdvantageE (HYB k ∘ SINGLE false)%pack (HYB k.+1 ∘ SINGLE true)%pack A = 0.
        { apply: hyb_step; solve_fsep. }
        rewrite Z addr0 -Advantage_link.
        by apply: Num.Theory.lerD.
    Qed.

    Theorem multi_instance_hybrid_sum :
      AdvantageE (MULTI true) (MULTI false) A
      <= \sum_(j < q) AdvantageE (SINGLE true) (SINGLE false) (A ∘ HYB j)%pack.
    Proof.
      have Z0 : AdvantageE (MULTI true) (HYB 0 ∘ SINGLE true)%pack A = 0.
      { apply: (multi_is_hyb true true 0).
        all: first [ solve_fsep | (move=> c _ Hc; by rewrite lt0n Hc) | done ]. }
      have Zq : AdvantageE (HYB q ∘ SINGLE true)%pack (MULTI false) A = 0.
      { rewrite Advantage_sym. apply: (multi_is_hyb false true q).
        all: first [ solve_fsep | (move=> c Hc _; by rewrite ltnNge (ltnW Hc))
                   | by rewrite ltnn ]. }
      eapply Order.POrderTheory.le_trans; first exact: (Advantage_triangle _ _ (HYB 0 ∘ SINGLE true)%pack).
      rewrite Z0 add0r.
      eapply Order.POrderTheory.le_trans; first exact: (Advantage_triangle _ _ (HYB q ∘ SINGLE true)%pack).
      rewrite Zq addr0.
      exact: hybrid_prefix.
    Qed.

    Corollary multi_instance_hybrid_bound (eps : R) :
      (∀ j, (j < q)%N → AdvantageE (SINGLE true) (SINGLE false) (A ∘ HYB j)%pack <= eps) →
      AdvantageE (MULTI true) (MULTI false) A <= eps *+ q.
    Proof.
      move=> H.
      eapply Order.POrderTheory.le_trans; first exact: multi_instance_hybrid_sum.
      have -> : eps *+ q = \sum_(j < q) eps by rewrite sumr_const card_ord.
      apply: Num.Theory.ler_sum => j _. exact: H.
    Qed.

  End Telescope.

End HybridInst.
