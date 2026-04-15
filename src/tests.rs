#[cfg(test)]

mod tests{
    use std::convert::TryFrom;
    use dashu::float::FBig;
    use dashu::float::round::mode::Zero;

    fn linspace(start: f64, end: f64, num: usize) -> Vec<f64> {
        (0..num).map(|i| start + (i as f64) * (end - start) / ((num - 1) as f64))
            .map(|i| i.round()).collect()
    }

    #[test]
    fn test_inverse() {
        let range_start = 1.0;
        let range_end = 2.0f64.powf(5.0);
        let num_points = 10;

        let values = linspace(range_start, range_end, num_points);

        for random in values {
            println!("Original: {:?}", random);

            let val: FBig<Zero,2> = FBig::try_from( random).unwrap();
            println!("FBig value: {:?}", val);

            let inverse = FBig::ONE / val;
            println!("Inverse: {:?}", inverse);
            println!("----------------------");
        }
    }

}