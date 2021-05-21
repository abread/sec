use crate::Position;

const NEIGHBOURHOOD_DISTANCE: usize = 100;

/// Defines whether a and b are neighbours (ie: should be able to communicate)
/// This is defined by the Manhattan distance between the nodes.
/// The Manhattan distance (also refered to grid distance or L1 distance) is just the sum of the
/// components in the difference vector.
///
/// Other interesting distances could be the Euclidean distance (plane distance or L2 distance) or,
/// more generally, the Ln distance.
///
/// The Ln distance is defined as the nth-root of the sum of the nth powers of the components of
/// the difference vector.
///
pub fn are_neighbours(a: Position, b: Position) -> bool {
    (((a.0 as isize - b.0 as isize) + (a.1 as isize - b.1 as isize)).abs() as usize)
        < NEIGHBOURHOOD_DISTANCE
}
