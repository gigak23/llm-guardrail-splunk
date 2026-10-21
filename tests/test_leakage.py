from guardrails.leakage import leakage_similarity
from guardrails.policy import Policy, evaluate_output

SP = "You are a helpful assistant for internal use only."


def test_verbatim_leakage_is_high():
    assert leakage_similarity(SP, SP) >= 0.85


def test_unrelated_output_is_low():
    assert leakage_similarity("The weather is sunny today.", SP) < 0.5


def test_output_policy_blocks_leakage():
    d = evaluate_output(SP, Policy(system_prompt=SP))
    assert d.decision == "BLOCK" and d.policy_id == "system_prompt_leakage"
