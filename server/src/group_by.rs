/// A safe, specialized implementation of libstd's std::iter::Iterator::group_by
/// that only works with slices
///
/// ```
/// # use server::group_by::group_by;
/// let v = vec![1, 2, 2, 3, 3, 3, 2, 2, 1];
/// let mut it = group_by(&v, |a, b| a == b);
///
/// assert_eq!(&[1], it.next().unwrap());
/// assert_eq!(&[2,2], it.next().unwrap());
/// assert_eq!(&[3,3,3], it.next().unwrap());
/// assert_eq!(&[2,2], it.next().unwrap());
/// assert_eq!(&[1], it.next().unwrap());
/// ```
pub fn group_by<T>(slice: &[T], pred: fn(&T, &T) -> bool) -> impl Iterator<Item=&[T]> {
    GroupBy {
        i: 0,
        slice,
        pred,
    }
}

struct GroupBy<'slice, T> {
    i: usize,
    slice: &'slice [T],
    pred: fn(&T, &T) -> bool
}

impl<'slice, T> Iterator for GroupBy<'slice, T> {
    type Item = &'slice [T];

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.slice.len() {
            None
        } else {
            let mut j = self.i + 1;

            while j < self.slice.len() && (self.pred)(&self.slice[j-1], &self.slice[j]) {
                j += 1;
            }

            let res = Some(&self.slice[self.i..j]);
            self.i = j; // advance iterator
            res
        }
    }
}

impl<'slice, T> std::iter::FusedIterator for GroupBy<'slice, T> {}

#[cfg(test)]
mod test {
    use super::group_by;

    #[test]
    fn single_element() {
        let v = vec![1];
        let mut it = group_by(&v, |a, b| a == b);
        assert_eq!(Some(v.as_slice()), it.next());
        assert_eq!(None, it.next());
    }

    #[test]
    fn empty() {
        let v: Vec<i32> = vec![];
        let mut it = group_by(&v, |a, b| a == b);
        assert_eq!(None, it.next());
        assert_eq!(None, it.next()); // fused
        assert_eq!(None, it.next());
        assert_eq!(None, it.next());
    }
}