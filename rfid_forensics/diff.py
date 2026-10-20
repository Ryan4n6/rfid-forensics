"""Compare two MIFARE Classic dumps to identify shared and divergent fields."""

from dataclasses import dataclass

from .dump_loader import MfcCard


@dataclass
class BlockDiff:
    """Difference between two blocks."""

    block: int
    sector: int
    card_a: bytes
    card_b: bytes
    byte_diffs: list[int]  # indices of differing bytes


@dataclass
class DumpComparison:
    """Full comparison of two card dumps."""

    card_a_uid: str
    card_b_uid: str
    same_type: bool
    shared_keys: list[str]
    different_keys: list[tuple[int, str, str, str]]  # sector, slot, key_a, key_b
    identical_blocks: list[int]
    different_blocks: list[BlockDiff]
    same_property: bool
    notes: list[str]


def compare_dumps(card_a: MfcCard, card_b: MfcCard) -> DumpComparison:
    """Compare two MIFARE Classic dumps sector by sector."""
    same_type = card_a.card_type == card_b.card_type
    num_sectors = min(card_a.num_sectors, card_b.num_sectors)

    keys_a = set()
    keys_b = set()
    shared_keys = []
    different_keys = []

    for s in range(num_sectors):
        ka_a = card_a.sector_keys.get(s, {}).get("KeyA", "").upper()
        ka_b = card_b.sector_keys.get(s, {}).get("KeyA", "").upper()
        kb_a = card_a.sector_keys.get(s, {}).get("KeyB", "").upper()
        kb_b = card_b.sector_keys.get(s, {}).get("KeyB", "").upper()

        if ka_a:
            keys_a.add(ka_a)
        if ka_b:
            keys_b.add(ka_b)

        if ka_a and ka_b and ka_a != ka_b:
            different_keys.append((s, "Key A", ka_a, ka_b))
        if kb_a and kb_b and kb_a != kb_b:
            different_keys.append((s, "Key B", kb_a, kb_b))

    shared_keys = sorted(keys_a & keys_b - {"FFFFFFFFFFFF", "000000000000"})
    same_property = len(shared_keys) > 0

    identical_blocks = []
    different_blocks = []

    max_blocks = min(len(card_a.blocks), len(card_b.blocks))
    for blk in range(max_blocks):
        data_a = card_a.blocks.get(blk, b'\x00' * 16)
        data_b = card_b.blocks.get(blk, b'\x00' * 16)

        sector = blk // 4 if blk < 128 else 32 + (blk - 128) // 16
        trailer = card_a.sector_trailer(sector)
        if blk == trailer:
            continue

        if data_a == data_b:
            identical_blocks.append(blk)
        else:
            byte_diffs = [i for i in range(16) if data_a[i] != data_b[i]]
            different_blocks.append(BlockDiff(
                block=blk, sector=sector,
                card_a=data_a, card_b=data_b,
                byte_diffs=byte_diffs,
            ))

    notes = []
    if same_property:
        notes.append(f"Cards share {len(shared_keys)} non-default key(s): likely same property.")
    if not different_keys:
        notes.append("All sector keys are identical between cards.")
    if len(different_blocks) == 0:
        notes.append("Card data is identical (excluding trailers).")
    else:
        notes.append(
            f"{len(different_blocks)} data block(s) differ. "
            f"These likely contain per-card credentials or audit data."
        )

    return DumpComparison(
        card_a_uid=card_a.uid,
        card_b_uid=card_b.uid,
        same_type=same_type,
        shared_keys=shared_keys,
        different_keys=different_keys,
        identical_blocks=identical_blocks,
        different_blocks=different_blocks,
        same_property=same_property,
        notes=notes,
    )


def format_comparison(comp: DumpComparison) -> str:
    """Format a dump comparison as readable text."""
    lines = []
    w = lines.append

    w("=" * 72)
    w("DUMP COMPARISON REPORT")
    w("=" * 72)
    w(f"Card A: {comp.card_a_uid}")
    w(f"Card B: {comp.card_b_uid}")
    w(f"Same card type: {'Yes' if comp.same_type else 'No'}")
    w(f"Same property:  {'Likely' if comp.same_property else 'Unknown'}")
    w("")

    if comp.shared_keys:
        w("Shared keys (non-default):")
        for k in comp.shared_keys:
            w(f"  {k}")
        w("")

    if comp.different_keys:
        w("Key differences:")
        for sector, slot, ka, kb in comp.different_keys:
            w(f"  Sector {sector} {slot}: A={ka}, B={kb}")
        w("")

    if comp.different_blocks:
        w(f"Data differences ({len(comp.different_blocks)} blocks):")
        for d in comp.different_blocks:
            hex_a = " ".join(f"{b:02X}" for b in d.card_a)
            hex_b = " ".join(f"{b:02X}" for b in d.card_b)
            w(f"  Sector {d.sector}, Block {d.block}:")
            w(f"    A: {hex_a}")
            w(f"    B: {hex_b}")
            w(f"    Differs at bytes: {d.byte_diffs}")
        w("")

    for note in comp.notes:
        w(f"  NOTE: {note}")

    return "\n".join(lines)
