Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum ssralg.
From mathcomp Require Import poly polydiv qpoly.
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

Module Type SeedParam.
  Parameter seed_size : nat.
End SeedParam.

Module Pke_scheme (Seed : SeedParam).
  Import Seed.

  Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
  Notation " 'ch ( x ) " := x (at level 2) : package_scope.

  Definition PKE_KGEN : ident := 10%N.
  Definition PKE_ENC  : ident := 11%N.
  Definition PKE_DEC  : ident := 12%N.

  Definition PKE_Scheme (Seed_t Message_t PublicKey_t SecretKey_t Ciphertext_t : choice_type) : Interface :=
    [interface
      #val #[ PKE_KGEN ] : 'unit → 'ch(chProd PublicKey_t SecretKey_t) ;
      #val #[ PKE_ENC ]  : 'ch(chProd (chProd PublicKey_t Message_t) Seed_t) → 'ch(Ciphertext_t) ;
      #val #[ PKE_DEC ]  : 'ch(chProd SecretKey_t Ciphertext_t) → 'ch(Message_t)
    ].

  Definition GEN : ident := 0%N.
  Definition CHALLENGE : ident := 1%N.

  Definition IND_CPA_exports (PublicKey_t Message_t Ciphertext_t : choice_type) : Interface :=
    [interface
      #val #[ GEN ] : 'unit → 'ch(PublicKey_t) ;
      #val #[ CHALLENGE ] : 'ch(chProd Message_t Message_t) → 'ch(Ciphertext_t)
    ].

  Definition mpk_loc (PublicKey_t : choice_type) := mkloc 1%N (None : option PublicKey_t).

  (* Track whether CHALLENGE has already been queried *)
  Definition queried_loc := mkloc 2%N false.

  Definition IND_CPA_Game
    (Message_t PublicKey_t SecretKey_t Ciphertext_t : choice_type)
    (b : bool) : package (PKE_Scheme (chFin seed_size) Message_t PublicKey_t SecretKey_t Ciphertext_t) (IND_CPA_exports PublicKey_t Message_t Ciphertext_t) :=
    [package [fmap mpk_loc PublicKey_t ; queried_loc] ;
      #def #[ GEN ] ('tt : 'unit) : 'ch(PublicKey_t) {
        pk_opt ← get (mpk_loc PublicKey_t) ;;
        (* Prevent multiple GEN calls: fail if a key has already been generated *)
        if pk_opt is Some _ then fail
        else
          #import {sig #[ PKE_KGEN ] : 'unit → 'ch(chProd PublicKey_t SecretKey_t) } as kgen_oracle ;;
          pk_sk ← kgen_oracle tt ;;
          #put (mpk_loc PublicKey_t) := Some pk_sk.1 ;;
          ret pk_sk.1
      } ;
      #def #[ CHALLENGE ] (m : 'ch(chProd Message_t Message_t)) : 'ch(Ciphertext_t) {
        pk_opt ← get (mpk_loc PublicKey_t) ;;
        queried ← get queried_loc ;;
        (* Enforce single challenge query and ensure GEN was called first *)
        if queried then fail else
        if pk_opt is Some pk then
          let m0 := m.1 in
          let m1 := m.2 in
          (* Note: Add length equality check here if Message_t is variable-length *)
          #put queried_loc := true ;;
          #import {sig #[ PKE_ENC ] : 'ch(chProd (chProd PublicKey_t Message_t) (chFin seed_size)) → 'ch(Ciphertext_t) } as enc_oracle ;;
          seed ← sample (uniform seed_size) ;;
          enc_oracle (pk, (if b then m1 else m0), seed)
        else
          fail
      }
    ].

  Definition IND_CPA
    {Message_t PublicKey_t SecretKey_t Ciphertext_t : choice_type} {I : Interface}
    (scheme : package I (PKE_Scheme (chFin seed_size) Message_t PublicKey_t SecretKey_t Ciphertext_t))
    (b : bool) : raw_package :=
    (pack (IND_CPA_Game Message_t PublicKey_t SecretKey_t Ciphertext_t b) ∘ pack scheme).

  Definition Adv_IND_CPA
    {Message_t PublicKey_t SecretKey_t Ciphertext_t : choice_type} {I : Interface}
    (scheme : package I (PKE_Scheme (chFin seed_size) Message_t PublicKey_t SecretKey_t Ciphertext_t))
    (A : adversary (IND_CPA_exports PublicKey_t Message_t Ciphertext_t)) : R :=
    Advantage (IND_CPA scheme) A.

End Pke_scheme.
