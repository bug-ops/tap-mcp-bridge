# ADR-001: Remove scripts/ Directory

## Status
Accepted (2025-11-10)

## Context

The project had a `scripts/verify.sh` shell script (120 lines) that duplicated functionality already provided by:
- **Makefile.toml** - Defines all verification tasks via cargo-make
- **GitHub Actions CI** - Automated execution of all checks across platforms
- **Direct cargo commands** - Always available, no abstraction needed

This created four different ways to run the same checks:
1. `scripts/verify.sh`
2. `cargo make verify`
3. GitHub Actions (automatic)
4. Direct cargo commands

The project follows MVP and compact solutions principles from CLAUDE.md:
- Compact solutions only - implement minimal functionality
- No convenience features - avoid syntactic sugar or "nice-to-have" additions
- Avoid duplication - DRY principle

## Decision

**Remove the `scripts/` directory entirely.**

Developers will use:
- **Local development**: `cargo make verify` or direct cargo commands
- **CI/CD**: GitHub Actions workflow (automated)
- **Pre-commit**: `cargo make pre-commit`

## Rationale

1. **Eliminates duplication** - Three execution paths instead of four
2. **Simplifies maintenance** - One less place to update when adding checks
3. **Cross-platform native** - cargo-make and cargo work identically on all Tier 1 platforms
4. **No unique value** - Shell script provided:
   - Colored output (nice-to-have, not essential)
   - Tool detection (cargo already handles this)
   - Error handling (cargo and make already provide)

5. **Aligns with CLAUDE.md principles**:
   - ✅ Compact - removed 120 unnecessary lines
   - ✅ No convenience - no wrapper abstraction
   - ✅ MVP mindset - minimal infrastructure

## Consequences

**Positive**:
- Simpler mental model for developers
- Less maintenance burden (one less file to update)
- No platform-specific shell concerns (bash on Windows)
- Clear separation: Makefile.toml (tasks), CI (automation), cargo (execution)

**Negative**:
- No colored output for local verification (minor)
- Developers need cargo-make installed for composite tasks
  - Mitigation: Direct cargo commands always work
  - Mitigation: Installation is documented and one-time

**Migration**:
- Replace `./scripts/verify.sh` → `cargo make verify`
- Replace custom scripts → Use Makefile.toml tasks or direct cargo commands

## Alternatives Considered

1. **Keep scripts/ with minimal wrapper**
   - Rejected: Still duplication, adds platform concerns

2. **Keep scripts/ for platform-specific setup**
   - Rejected: No platform-specific setup needed (Cargo.toml handles everything)

3. **Remove Makefile.toml, keep scripts/**
   - Rejected: cargo-make is cross-platform, more maintainable than shell scripts

## References

- CLAUDE.md Development Approach section
- Makefile.toml task definitions
- .github/workflows/ci.yml automation
