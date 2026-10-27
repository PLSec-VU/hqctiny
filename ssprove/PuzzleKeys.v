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

Section PuzzleKeys.

  Context (cookie_key_bits cookie_nonce_bits cookie_bits mac_key_bits coins_key_bits coins_bits
    : nat).
  Context (CookiePlain_t MacIn_t PuzzleTag_t CoinsIn_t PlainIn_t Answer_t : choice_type).

  #[local] Notation CookieKey := (CookieKey_t cookie_key_bits).
  #[local] Notation Cookie := (Cookie_t cookie_bits).

  Definition MacKey_t := chFin (2 ^ mac_key_bits).
  Definition CoinsKey_t := chFin (2 ^ coins_key_bits).
  Definition Coins_t := chFin (2 ^ coins_bits).
  Definition Solved_t := chProd (chProd MacIn_t PuzzleTag_t) (chProd CoinsIn_t PlainIn_t).

  Context (seal_cookie : CookieKey → CookiePlain_t → 'I_(2 ^ cookie_nonce_bits) → Cookie).
  Context (open_cookie : CookieKey → Cookie → option CookiePlain_t).
  Context (mac_key_of : CookieKey → MacKey_t).
  Context (coins_key_of : CookieKey → CoinsKey_t).
  Context (puzzle_mac : MacKey_t → MacIn_t → PuzzleTag_t).
  Context (puzzle_coins : CoinsKey_t → CoinsIn_t → Coins_t).
  Context (solution_ok : MacIn_t → CoinsIn_t → bool).
  Context (plain_of : PlainIn_t → Coins_t → CookiePlain_t).
  Context (nonce_of : Coins_t → 'I_(2 ^ cookie_nonce_bits)).
  Context (answer : CookiePlain_t → Answer_t).

  Definition valid_solution (tag : PuzzleTag_t) (expected : PuzzleTag_t) (x : MacIn_t)
    (y : CoinsIn_t) : bool :=
    (tag == expected) && solution_ok x y.

  #[local] Notation ckey_loc := (key_loc cookie_key_bits).
  Definition mkey_loc : Location := mkloc 100 (None : 'option MacKey_t).
  Definition ckoins_loc : Location := mkloc 101 (None : 'option CoinsKey_t).
  Definition coins_tab_loc : Location := mkloc 102 (emptym : chMap CoinsIn_t Coins_t).

  Definition SEAL_N : ident := 103%N.
  Definition OPEN_C : ident := 104%N.
  Definition PMAC : ident := 105%N.
  Definition PCOINS : ident := 106%N.
  Definition ISSUE_CHAL : ident := 107%N.
  Definition SOLVED : ident := 108%N.
  Definition REQUEST_P : ident := 109%N.

  Definition I_keysep : Interface :=
    [interface
      #val #[ SEAL_N ] : 'ch(chProd CookiePlain_t ('fin (2 ^ cookie_nonce_bits))) → 'ch(Cookie) ;
      #val #[ OPEN_C ] : 'ch(Cookie) → 'ch(chOption CookiePlain_t) ;
      #val #[ PMAC ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t) ;
      #val #[ PCOINS ] : 'ch(CoinsIn_t) → 'ch(Coins_t) ].

  Definition I_coins : Interface :=
    [interface #val #[ PCOINS ] : 'ch(CoinsIn_t) → 'ch(Coins_t) ].

  Definition I_puzzle : Interface :=
    [interface
      #val #[ ISSUE_CHAL ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t) ;
      #val #[ SOLVED ] : 'ch(Solved_t) → 'ch(chOption Cookie) ;
      #val #[ REQUEST_P ] : 'ch(Cookie) → 'ch(chOption Answer_t) ].

  Definition KeySepReal : package emptym I_keysep :=
    [package [fmap ckey_loc] ;
      #def #[ SEAL_N ] (q : 'ch(chProd CookiePlain_t ('fin (2 ^ cookie_nonce_bits))))
          : 'ch(Cookie) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (seal_cookie ck q.1 q.2)
      } ;
      #def #[ OPEN_C ] (c : 'ch(Cookie)) : 'ch(chOption CookiePlain_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (open_cookie ck c)
      } ;
      #def #[ PMAC ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac (mac_key_of ck) x)
      } ;
      #def #[ PCOINS ] (y : 'ch(CoinsIn_t)) : 'ch(Coins_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_coins (coins_key_of ck) y)
      }
    ].

  Definition KeySepIdeal : package emptym I_keysep :=
    [package [fmap ckey_loc ; mkey_loc ; ckoins_loc] ;
      #def #[ SEAL_N ] (q : 'ch(chProd CookiePlain_t ('fin (2 ^ cookie_nonce_bits))))
          : 'ch(Cookie) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (seal_cookie ck q.1 q.2)
      } ;
      #def #[ OPEN_C ] (c : 'ch(Cookie)) : 'ch(chOption CookiePlain_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (open_cookie ck c)
      } ;
      #def #[ PMAC ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ PCOINS ] (y : 'ch(CoinsIn_t)) : 'ch(Coins_t) {
        cc ← get ckoins_loc ;;
        kc ← (match cc with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ coins_key_bits) ;;
                        #put ckoins_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_coins kc y)
      }
    ].

  Definition CoinsPrfReal : package emptym I_coins :=
    [package [fmap ckoins_loc] ;
      #def #[ PCOINS ] (y : 'ch(CoinsIn_t)) : 'ch(Coins_t) {
        cc ← get ckoins_loc ;;
        kc ← (match cc with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ coins_key_bits) ;;
                        #put ckoins_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_coins kc y)
      }
    ].

  Definition CoinsPrfIdeal : package emptym I_coins :=
    [package [fmap coins_tab_loc] ;
      #def #[ PCOINS ] (y : 'ch(CoinsIn_t)) : 'ch(Coins_t) {
        T ← get coins_tab_loc ;;
        match T y with
        | Some cs => ret cs
        | None =>
            cs ← sample uniform (2 ^ coins_bits) ;;
            #put coins_tab_loc := setm T y cs ;;
            ret cs
        end
      }
    ].

  Definition PuzzleServer : package emptym I_puzzle :=
    [package [fmap ckey_loc] ;
      #def #[ ISSUE_CHAL ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac (mac_key_of ck) x)
      } ;
      #def #[ SOLVED ] (s : 'ch(Solved_t)) : 'ch(chOption Cookie) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        if valid_solution s.1.2 (puzzle_mac (mac_key_of ck) s.1.1) s.1.1 s.2.1 then
          kk' ← get ckey_loc ;;
          ck' ← (match kk' with
                 | Some k => ret k
                 | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                           #put ckey_loc := Some k ;;
                           ret k
                 end) ;;
          let cs := puzzle_coins (coins_key_of ck') s.2.1 in
          kk'' ← get ckey_loc ;;
          ck'' ← (match kk'' with
                  | Some k => ret k
                  | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                            #put ckey_loc := Some k ;;
                            ret k
                  end) ;;
          ret (Some (seal_cookie ck'' (plain_of s.2.2 cs) (nonce_of cs)))
        else ret None
      } ;
      #def #[ REQUEST_P ] (c : 'ch(Cookie)) : 'ch(chOption Answer_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (omap answer (open_cookie ck c))
      }
    ].

  Definition R_keysep : package I_keysep I_puzzle :=
    [package emptym ;
      #def #[ ISSUE_CHAL ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        #import {sig #[ PMAC ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t)} as pmac ;;
        t ← pmac x ;;
        ret t
      } ;
      #def #[ SOLVED ] (s : 'ch(Solved_t)) : 'ch(chOption Cookie) {
        #import {sig #[ PMAC ] : 'ch(MacIn_t) → 'ch(PuzzleTag_t)} as pmac ;;
        #import {sig #[ PCOINS ] : 'ch(CoinsIn_t) → 'ch(Coins_t)} as pcoins ;;
        #import {sig #[ SEAL_N ] : 'ch(chProd CookiePlain_t ('fin (2 ^ cookie_nonce_bits)))
                                     → 'ch(Cookie)} as seal ;;
        t ← pmac s.1.1 ;;
        if valid_solution s.1.2 t s.1.1 s.2.1 then
          cs ← pcoins s.2.1 ;;
          c ← seal (plain_of s.2.2 cs, nonce_of cs) ;;
          ret (Some c)
        else ret None
      } ;
      #def #[ REQUEST_P ] (c : 'ch(Cookie)) : 'ch(chOption Answer_t) {
        #import {sig #[ OPEN_C ] : 'ch(Cookie) → 'ch(chOption CookiePlain_t)} as open ;;
        r ← open c ;;
        ret (omap answer r)
      }
    ].

  Definition PuzzleServerSeparate : package emptym I_puzzle :=
    [package [fmap ckey_loc ; mkey_loc ; ckoins_loc] ;
      #def #[ ISSUE_CHAL ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED ] (s : 'ch(Solved_t)) : 'ch(chOption Cookie) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        if valid_solution s.1.2 (puzzle_mac km s.1.1) s.1.1 s.2.1 then
          cc ← get ckoins_loc ;;
          kc ← (match cc with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ coins_key_bits) ;;
                          #put ckoins_loc := Some k ;;
                          ret k
                end) ;;
          let cs := puzzle_coins kc s.2.1 in
          kk ← get ckey_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put ckey_loc := Some k ;;
                          ret k
                end) ;;
          ret (Some (seal_cookie ck (plain_of s.2.2 cs) (nonce_of cs)))
        else ret None
      } ;
      #def #[ REQUEST_P ] (c : 'ch(Cookie)) : 'ch(chOption Answer_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (omap answer (open_cookie ck c))
      }
    ].

  Definition R_coins : package I_coins I_puzzle :=
    [package [fmap ckey_loc ; mkey_loc] ;
      #def #[ ISSUE_CHAL ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED ] (s : 'ch(Solved_t)) : 'ch(chOption Cookie) {
        #import {sig #[ PCOINS ] : 'ch(CoinsIn_t) → 'ch(Coins_t)} as pcoins ;;
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        if valid_solution s.1.2 (puzzle_mac km s.1.1) s.1.1 s.2.1 then
          cs ← pcoins s.2.1 ;;
          kk ← get ckey_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put ckey_loc := Some k ;;
                          ret k
                end) ;;
          ret (Some (seal_cookie ck (plain_of s.2.2 cs) (nonce_of cs)))
        else ret None
      } ;
      #def #[ REQUEST_P ] (c : 'ch(Cookie)) : 'ch(chOption Answer_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (omap answer (open_cookie ck c))
      }
    ].

  Definition PuzzleServerRandomCoins : package emptym I_puzzle :=
    [package [fmap ckey_loc ; mkey_loc ; coins_tab_loc] ;
      #def #[ ISSUE_CHAL ] (x : 'ch(MacIn_t)) : 'ch(PuzzleTag_t) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        ret (puzzle_mac km x)
      } ;
      #def #[ SOLVED ] (s : 'ch(Solved_t)) : 'ch(chOption Cookie) {
        mm ← get mkey_loc ;;
        km ← (match mm with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ mac_key_bits) ;;
                        #put mkey_loc := Some k ;;
                        ret k
              end) ;;
        if valid_solution s.1.2 (puzzle_mac km s.1.1) s.1.1 s.2.1 then
          T ← get coins_tab_loc ;;
          cs ← (match T s.2.1 with
                | Some cs => ret cs
                | None =>
                    cs ← sample uniform (2 ^ coins_bits) ;;
                    #put coins_tab_loc := setm T s.2.1 cs ;;
                    ret cs
                end) ;;
          kk ← get ckey_loc ;;
          ck ← (match kk with
                | Some k => ret k
                | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                          #put ckey_loc := Some k ;;
                          ret k
                end) ;;
          ret (Some (seal_cookie ck (plain_of s.2.2 cs) (nonce_of cs)))
        else ret None
      } ;
      #def #[ REQUEST_P ] (c : 'ch(Cookie)) : 'ch(chOption Answer_t) {
        kk ← get ckey_loc ;;
        ck ← (match kk with
              | Some k => ret k
              | None => k ← sample uniform (2 ^ cookie_key_bits) ;;
                        #put ckey_loc := Some k ;;
                        ret k
              end) ;;
        ret (omap answer (open_cookie ck c))
      }
    ].

  Ltac sync_step :=
    ssprove_code_simpl; try (progress cbv zeta);
    first
      [ match goal with
        | |- context [ match ?mk with Some _ => _ | None => _ end ] =>
            case: mk => [?|] /=
        end
      | match goal with
        | |- context [ if ?c then _ else _ ] => case: c => /=
        end
      | ssprove_sync_eq => ?
      | ssprove_sync_eq ].

  Ltac close_same :=
    eapply rpost_weaken_rule; [apply rreflexivity_rule | by move=> [? ?] [? ?] [-> ->]].


  Lemma puzzle_server_is_keysep_reduction : PuzzleServer ≈₀ (R_keysep ∘ KeySepReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma keysep_ideal_is_separate : (R_keysep ∘ KeySepIdeal)%pack ≈₀ PuzzleServerSeparate.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma separate_is_coins_reduction : PuzzleServerSeparate ≈₀ (R_coins ∘ CoinsPrfReal)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Lemma coins_ideal_is_random : (R_coins ∘ CoinsPrfIdeal)%pack ≈₀ PuzzleServerRandomCoins.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel x.
    all: simplify_linking.
    all: repeat sync_step.
    all: try close_same.
  Qed.

  Theorem puzzle_key_separation :
    ∀ LA A,
      ValidPackage LA I_puzzle A_export A →
      fseparate LA [fmap ckey_loc] →
      fseparate LA [fmap mkey_loc] →
      fseparate LA [fmap ckoins_loc] →
      fseparate LA [fmap coins_tab_loc] →
      AdvantageE PuzzleServer PuzzleServerRandomCoins A
      <= AdvantageE KeySepReal KeySepIdeal (A ∘ R_keysep)%pack
         + AdvantageE CoinsPrfReal CoinsPrfIdeal (A ∘ R_coins)%pack.
  Proof.
    move=> LA A VA S1 S2 S3 S4.
    ssprove triangle PuzzleServer [::
      (R_keysep ∘ KeySepReal)%pack ;
      (R_keysep ∘ KeySepIdeal)%pack ;
      pack PuzzleServerSeparate ;
      (R_coins ∘ CoinsPrfReal)%pack ;
      (R_coins ∘ CoinsPrfIdeal)%pack
    ] PuzzleServerRandomCoins A as ineq.
    eapply Order.POrderTheory.le_trans; first exact: ineq.
    have Z1 : AdvantageE PuzzleServer (R_keysep ∘ KeySepReal)%pack A = 0.
    { apply: puzzle_server_is_keysep_reduction; solve_fsep. }
    have Z2 : AdvantageE (R_keysep ∘ KeySepIdeal)%pack PuzzleServerSeparate A = 0.
    { apply: keysep_ideal_is_separate; solve_fsep. }
    have Z3 : AdvantageE PuzzleServerSeparate (R_coins ∘ CoinsPrfReal)%pack A = 0.
    { apply: separate_is_coins_reduction; solve_fsep. }
    have Z4 : AdvantageE (R_coins ∘ CoinsPrfIdeal)%pack PuzzleServerRandomCoins A = 0.
    { apply: coins_ideal_is_random; solve_fsep. }
    rewrite Z1 Z2 Z3 Z4 GRing.add0r !GRing.addr0.
    by rewrite !Advantage_link.
  Qed.

End PuzzleKeys.
