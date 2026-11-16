"""Counted classical implicit-rejection simulator and its resource envelope.

This reference is a proof instrument. It is not a KEM, does not replace
Decaps, and never accepts a challenge ciphertext as a decryption query.
It implements the lazy message/ciphertext lists used in the HHK ROM route.
"""
from collections import Counter
from fractions import Fraction
from itertools import product

from m10_security_sampler import natural, require


class CandidateFound(Exception):
    """A message whose deterministic encryption is the challenge was queried."""


class CountedImplicitSimulator:
    def __init__(self, encrypt, random_key, coin_oracle, challenge=None):
        self.encrypt=encrypt
        self.random_key=random_key
        self.coin_oracle=coin_oracle
        self.challenge=challenge
        self.coins=[]
        self.messages=[]
        self.ciphertexts=[]
        self.stats=Counter()

    def find(self, table, key):
        for stored,value in table:
            self.stats["tuple_comparisons"]+=1
            if stored==key:
                return value
        return None

    def coins_for(self,message):
        self.stats["coin_requests"]+=1
        value=self.find(self.coins,message)
        if value is None:
            self.stats["fresh_F_queries"]+=1
            value=self.coin_oracle(message)
            require(value is not None,"the coin oracle must return a value")
            self.coins.append((message,value))
        return value

    def key_for(self,message):
        self.stats["key_requests"]+=1
        value=self.find(self.messages,message)
        if value is not None:
            return value
        coins=self.coins_for(message)
        self.stats["public_encryptions"]+=1
        ciphertext=self.encrypt(message,coins)
        if ciphertext==self.challenge:
            self.stats["challenge_candidates"]+=1
            raise CandidateFound(message)
        key=self.find(self.ciphertexts,ciphertext)
        if key is None:
            key=self.random_key()
            require(key is not None,"the key tape must return a value")
            self.stats["fresh_keys"]+=1
            self.ciphertexts.append((ciphertext,key))
        self.messages.append((message,key))
        return key

    def g512_target(self,message):
        """The actual target-context query returns both F(m) and K(m)."""
        self.stats["target_G512_queries"]+=1
        return self.coins_for(message),self.key_for(message)

    def decap(self,ciphertext):
        self.stats["decapsulation_requests"]+=1
        require(ciphertext!=self.challenge,"challenge decapsulation forbidden")
        key=self.find(self.ciphertexts,ciphertext)
        if key is None:
            key=self.random_key()
            require(key is not None,"the key tape must return a value")
            self.stats["fresh_keys"]+=1
            self.ciphertexts.append((ciphertext,key))
        return key


def rom_resource_envelope(g512,shake256,shake128,hash256,decapsulations,word_limit=512):
    """One CPA branch (HHK C or D), not a sum over all proof hybrids.

    Auxiliary public PKE computations retain the seeded N oracle even when
    the honest key/challenge noise is replaced in the CPA hybrid. There are
    thirteen N calls and thirty-six matrix-cell reads per public Encrypt.
    Hashing the fixed public key context once is enough for this simulator.
    All payload sizes exclude allocator/index/runtime overhead and A's state.
    """
    g,j,a,h,d=(natural(g512,"g512"),natural(shake256,"shake256"),
               natural(shake128,"shake128"),natural(hash256,"hash256"),
               natural(decapsulations,"decapsulations"))
    natural(word_limit,"word_limit",65536)
    require(word_limit>=256,"the bounded reduction must permit a complete polynomial")
    # Cache each message's coins. The +1 covers the deterministic challenge.
    return dict(public_encryptions_max=g,public_and_challenge_encryptions_max=g+1,
        F_requests_max=2*g+1,distinct_F_oracle_queries_max=g+1,
        KG_queries_max=g,N_queries_max=j+13*g,A_cell_reads_max=a+36*g,Hpk_queries_max=h+1,
        tuple_comparisons_max=(4*g+2*d+4)**2,
        maximum_tuple_key_bytes=2656,
        message_list_payload_bytes_max=(32+32)*g,
        ciphertext_list_payload_bytes_max=(2656+32)*(g+d),
        coin_list_payload_bytes_max=(32+32)*(g+1),
        scalar_choice_payload_bytes=64,
        challenge_payload_bytes=2656+32,
        matrix_setup_candidate_limit_per_cell=word_limit,
        matrix_setup_prefix_bytes_max=2*36*word_limit,
        public_matrix_cached_for_bounded_Encrypt=True,
        time_formula="T_A+(g+1)*T_Enc_given_A_bound+C*Cmp_2656+T_matrix_setup+T_aux_oracle_tables(Q,input_and_prefix_bytes)",
        C_formula="(4*g+2*D+4)^2",
        extra_oracle_payloads_and_original_adversary_state_excluded=True,
        C_and_D_branches_use_same_maximum_envelope=True,
        full_concrete_gate_or_memory_calibration_supplied=False)


def finite_simulator_law_checks():
    """Compare full joint transcripts for an injective toy deterministic PKE.

    Two messages map to ciphertexts 0/1, and ciphertext2 is invalid. Every
    key tape is enumerated. The true oracle samples independent K(0),K(1),
    J(2); the simulator samples lazily by ciphertext. Repeated and reordered
    key/Decap queries must have EXACTLY the same joint law.
    """
    actions=(("G",0),("G",1),("D",0),("D",1),("D",2))
    panels=transcripts=0
    for length in range(5):
        for sequence in product(actions,repeat=length):
            true=Counter()
            simulated=Counter()
            for tape in product(range(2),repeat=3):
                keys={0:tape[0],1:tape[1],2:tape[2]}
                true[tuple((m%2,keys[m]) if kind=="G" else keys[m] for kind,m in sequence)]+=1
                iterator=iter(tape)
                sim=CountedImplicitSimulator(lambda m,_coins:m,lambda:next(iterator),lambda m:m%2)
                simulated[tuple(sim.g512_target(m) if kind=="G" else sim.decap(m)
                                for kind,m in sequence)]+=1
                g=sum(kind=="G" for kind,_ in sequence)
                d=length-g
                bound=rom_resource_envelope(g,0,0,0,d)
                require(sim.stats["public_encryptions"]<=bound["public_encryptions_max"],"public encryption cap failed")
                require(sim.stats["coin_requests"]<=bound["F_requests_max"],"F request cap failed")
                require(sim.stats["fresh_F_queries"]<=bound["distinct_F_oracle_queries_max"],"F cache cap failed")
                require(sim.stats["tuple_comparisons"]<=bound["tuple_comparisons_max"],"tuple comparison cap failed")
                transcripts+=1
            require(simulated==true,"implicit simulator joint transcript law differs")
            panels+=1
    # The challenge remains forbidden and finding its message stops extraction.
    sim=CountedImplicitSimulator(lambda m,_:m,lambda:0,lambda m:m,challenge=0)
    try:
        sim.decap(0)
    except ValueError:
        pass
    else:
        raise ValueError("challenge Decap was not forbidden")
    try:
        sim.g512_target(0)
    except CandidateFound as found:
        require(found.args==(0,),"wrong extracted candidate")
    else:
        raise ValueError("challenge-key query was not extracted")
    return dict(panels=panels,enumerated_true_and_simulator_tapes=transcripts,
        exact_joint_transcript_laws_equal=True,repetitions_and_reordering_included=True,
        source_G512_returns_both_coordinates=True,challenge_decap_forbidden=True,
        scope="finite injective toy simulator plus counted operation envelope, not a general proof or R1 execution")


def finite_adaptive_correctness_checks():
    """Every fresh examined F point is charged, including discarded searches.

    A fixed key's pointwise beta dominates every message. Key-dependent
    adaptive choices, repeated queries and coin-dependent second messages
    are exhaustively enumerated here, with the key even revealed to A.
    """
    panels, tables = 0, 0
    for key in (0,1):
        # Message key fails at coin0; the other message fails at coin1.
        failure=lambda message,coin: coin==(0 if message==key else 1)
        beta=Fraction(1,3)
        for first in (0,1):
            for policy in product((0,1),repeat=3):
                failed=0
                expected_distinct=Fraction(0)
                for values in product(range(3),repeat=2):
                    second=policy[values[first]]
                    failed+=failure(first,values[first]) or failure(second,values[second])
                    expected_distinct+=Fraction(1+(second!=first),9)
                    tables+=1
                # The deterministic cap2 suffices even when the stopping rule
                # and repeated-query pattern depend on prior oracle answers.
                require(Fraction(failed,9)<=2*beta,"adaptive correction union bound failed")
                require(Fraction(failed,9)<=expected_distinct*beta,
                        "finite fresh-query stopping bound failed")
                panels+=1
    # Search both points, then select a failing one: counting only the final
    # chosen encryption would incorrectly use beta rather than2*beta.
    search_success=Fraction(sum(a==0 or b==0 for a,b in product(range(3),repeat=2)),9)
    require(search_success==Fraction(5,9) and search_success>Fraction(1,3),
            "discarded-query negative witness missing")
    # A revealed key makes max-before-expectation essential.
    fixed_message_average=Fraction(sum(message==key and coin==0
        for key,coin,message in product((0,1),range(3),(0,))),6)
    key_dependent_message_failure=Fraction(sum(coin==0 for key,coin in product((0,1),range(3))),6)
    require(key_dependent_message_failure>fixed_message_average,
            "key-dependent message negative witness missing")
    return dict(adaptive_policies=panels,enumerated_key_and_oracle_tables=tables,
        all_pointwise_beta_union_bounds_pass=True,
        discarded_query_search_success=search_success,incorrect_final_query_only_bound=Fraction(1,3),
        max_m_after_key_average_is_required=True,
        scope="finite adaptive witnesses, not a full R1 failure probability experiment")
