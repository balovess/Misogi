//! Interleaver for dispersing burst packet losses across FEC shards.
//!
//! Optical data diodes often lose packets in bursts (e.g., during brief
//! optical power fluctuations). If consecutive shards are lost, standard
//! Reed-Solomon decoding may fail even if total loss is within tolerance.
//!
//! The interleaver reorders shard transmission so that logically adjacent
//! shards are transmitted far apart in time/space, converting burst losses
//! into scattered single-shard losses that RS coding handles optimally.
//!
//! # Example (4-way interleave)
//!
//! Logical order:  [S0, S1, S2, S3, S4, S5, S6, S7, ...]
//! Transmit order: [S0, S4, S8, ..., S1, S5, S9, ..., S2, S6, S10, ..., S3, S7, S11, ...]
//!
//! Burst loss of 3 consecutive packets:
//! - Without interleave: loses [S4, S5, S6] = 3 shards in one RS group
//! - With interleave: loses [S4, S1, S5] = 1 shard each across 3 groups

/// Interleave factor (number of groups to spread shards across).
const DEFAULT_INTERLEAVE_WIDTH: usize = 4;

/// Burst loss disperser that reorders shard transmission order.
///
/// Converts consecutive logical shard indices into a scattered physical
/// transmission sequence, ensuring that a burst of N consecutive lost
/// packets affects at most `ceil(N / width)` shards per any single RS group.
///
/// # Thread Safety
///
/// This struct is stateless after construction and can be freely shared
/// across threads (`Send + Sync` derived via `Debug, Clone`).
#[derive(Debug, Clone)]
pub struct Interleaver {
    /// Number of groups to distribute shards across.
    ///
    /// Higher values provide better burst-loss resistance at the cost of
    /// increased reorder buffer depth. Must be >= 2.
    width: usize,

    /// Total number of shards in the encoding block (data + parity).
    total_shards: usize,
}

impl Interleaver {
    /// Create interleaver with default width (4) for given shard count.
    ///
    /// # Arguments
    /// * `total_shards` - Total number of data + parity shards.
    pub fn new(total_shards: usize) -> Self {
        Self::with_width(total_shards, DEFAULT_INTERLEAVE_WIDTH)
    }

    /// Create interleaver with custom interleave width.
    ///
    /// # Arguments
    /// * `total_shards` - Total number of data + parity shards.
    /// * `width` - Number of interleaving groups (must be >= 2).
    ///
    /// # Panics
    ///
    /// Panics if `width < 2` or `width > total_shards`.
    pub fn with_width(total_shards: usize, width: usize) -> Self {
        assert!(width >= 2, "Interleave width must be >= 2");
        assert!(
            width <= total_shards,
            "Interleave width ({}) cannot exceed total_shards ({})",
            width,
            total_shards
        );
        Self { width, total_shards }
    }

    /// Compute the transmission order for all logical shard indices.
    ///
    /// Returns a vector where `result[i]` = logical index of the i-th
    /// packet to transmit. The sender iterates this vector and sends
    /// shards in the returned order.
    ///
    /// # Algorithm
    ///
    /// Uses row-major matrix reordering:
    ///
    /// ```text
    /// Group 0:  S0     S4     S8     S12   ...
    /// Group 1:  S1     S5     S9     S13   ...
    /// Group 2:  S2     S6     S10    S14   ...
    /// Group 3:  S3     S7     S11    S15   ...
    ///
    /// Transmit: [S0,S4,S8,..., S1,S5,S9,..., S2,S6,S10,..., S3,S7,S11,...]
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::fec::interleaver::Interleaver;
    /// let il = Interleaver::new(8);
    /// assert_eq!(il.compute_transmit_order(), vec![0, 4, 1, 5, 2, 6, 3, 7]);
    /// ```
    pub fn compute_transmit_order(&self) -> Vec<usize> {
        let mut order = Vec::with_capacity(self.total_shards);
        for group in 0..self.width {
            let mut idx = group;
            while idx < self.total_shards {
                order.push(idx);
                idx += self.width;
            }
        }
        order
    }

    /// Map a received physical position back to its logical shard index.
    ///
    /// This is the inverse of [`compute_transmit_order`](Self::compute_transmit_order).
    /// Given that the N-th transmitted packet carried which logical shard?
    ///
    /// # Arguments
    /// * `physical_idx` - Position in the transmission sequence (0-based).
    ///
    /// # Returns
    ///
    /// The logical shard index that was transmitted at this position.
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::fec::interleaver::Interleaver;
    /// let il = Interleaver::new(16);
    /// let order = il.compute_transmit_order();
    /// // Physical position 0 carries logical shard 0
    /// assert_eq!(il.physical_to_logical(0), 0);
    /// // Physical position 1 carries logical shard 4
    /// assert_eq!(il.physical_to_logical(1), 4);
    /// ```
    pub fn physical_to_logical(&self, physical_idx: usize) -> usize {
        let shards_per_group = (self.total_shards + self.width - 1) / self.width;
        let group = physical_idx / shards_per_group;
        let offset_in_group = physical_idx % shards_per_group;
        group + offset_in_group * self.width
    }

    /// Map a logical shard index to its physical transmission position.
    ///
    /// # Arguments
    /// * `logical_idx` - Logical shard index (0..total_shards).
    ///
    /// # Returns
    ///
    /// The position in the transmit sequence where this shard appears.
    ///
    /// # Example
    ///
    /// ```
    /// use misogi_core::fec::interleaver::Interleaver;
    /// let il = Interleaver::new(12);
    /// // Logical shard 0 is transmitted first (position 0)
    /// assert_eq!(il.logical_to_physical(0), 0);
    /// // Logical shard 1 is transmitted at position 4
    /// assert_eq!(il.logical_to_physical(1), 4);
    /// ```
    pub fn logical_to_physical(&self, logical_idx: usize) -> usize {
        let group = logical_idx % self.width;
        let offset_in_group = logical_idx / self.width;
        let shards_per_group = (self.total_shards + self.width - 1) / self.width;
        group * shards_per_group + offset_in_group
    }

    /// Returns the configured interleave width.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Returns the total shard count this interleaver was built for.
    pub fn total_shards(&self) -> usize {
        self.total_shards
    }
}

impl Default for Interleaver {
    fn default() -> Self {
        Self::new(20)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_4_way_interleave() {
        let il = Interleaver::new(8);
        let order = il.compute_transmit_order();
        assert_eq!(order.len(), 8);
        assert_eq!(order, vec![0, 4, 1, 5, 2, 6, 3, 7]);
    }

    #[test]
    fn test_interleave_is_permutation() {
        let il = Interleaver::new(20);
        let order = il.compute_transmit_order();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(sorted, (0..20).collect::<Vec<_>>());
    }

    #[test]
    fn test_physical_to_logical_roundtrip() {
        let il = Interleaver::new(16);
        let order = il.compute_transmit_order();
        for (phys, &log) in order.iter().enumerate() {
            assert_eq!(
                il.physical_to_logical(phys),
                log,
                "physical_to_logical({}) should be {}",
                phys,
                log
            );
        }
    }

    #[test]
    fn test_logical_to_physical_inverse() {
        let il = Interleaver::new(12);
        for log in 0..12 {
            let phys = il.logical_to_physical(log);
            assert_eq!(
                il.physical_to_logical(phys),
                log,
                "Roundtrip failed for logical index {}",
                log
            );
        }
    }

    #[test]
    fn test_burst_loss_scattering() {
        let il = Interleaver::new(20);
        let lost_logical: Vec<usize> = (5..=7)
            .map(|p| il.physical_to_logical(p))
            .collect();
        let groups: std::collections::HashSet<usize> =
            lost_logical.iter().map(|&l| l % il.width).collect();
        assert!(
            groups.len() <= 2,
            "Burst loss should scatter across groups, got {:?}",
            groups
        );
    }

    #[test]
    fn test_custom_width() {
        let il = Interleaver::with_width(9, 3);
        assert_eq!(il.width(), 3);
        let order = il.compute_transmit_order();
        assert_eq!(order.len(), 9);
        assert_eq!(order, vec![0, 3, 6, 1, 4, 7, 2, 5, 8]);
    }

    #[test]
    fn test_default_total_shards() {
        let il = Interleaver::default();
        assert_eq!(il.total_shards(), 20);
        assert_eq!(il.width(), 4);
    }

    #[test]
    #[should_panic(expected = "width must be >= 2")]
    fn test_panic_on_width_too_small() {
        let _ = Interleaver::with_width(10, 1);
    }

    #[test]
    #[should_panic(expected = "cannot exceed")]
    fn test_panic_on_width_exceeds_total() {
        let _ = Interleaver::with_width(5, 10);
    }

    #[test]
    fn test_minimal_case() {
        // Use with_width directly to test minimal 2-shard interleaving
        let il = Interleaver::with_width(2, 2);
        assert_eq!(il.compute_transmit_order(), vec![0, 1]);
    }

    #[test]
    fn test_prime_shard_count() {
        let il = Interleaver::new(17);
        let order = il.compute_transmit_order();
        assert_eq!(order.len(), 17);
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(sorted, (0..17).collect::<Vec<_>>());
    }
}
