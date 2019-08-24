use std::sync::Arc;
use std::sync::Mutex;

use futures::lock::Mutex as Mutex2;

use bencher::{benchmark_group, benchmark_main, Bencher};

fn bench_sync(b: &mut Bencher) {
    let x = Arc::new(Mutex::new(()));
    b.iter(|| {
        let _ = x.clone().lock().unwrap();
    })
}

fn bench_async(b: &mut Bencher) {
    let x = Arc::new(Mutex2::new(()));
    b.iter(|| {
        let _ = futures::executor::block_on(x.clone().lock());
    })
}

fn bench_none(b: &mut Bencher) {
    let x = Arc::new(());
    b.iter(|| {
        let _ = x.clone().as_ref();
    })
}

benchmark_group!(benches, bench_sync, bench_async, bench_none);
benchmark_main!(benches);
