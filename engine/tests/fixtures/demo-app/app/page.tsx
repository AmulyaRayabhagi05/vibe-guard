export default function Home({ onBuy }) {
  return (
    <main>
      <img src="/hero.png" />
      <div className="card" onClick={() => onBuy()}>Buy now</div>
      <input type="email" placeholder="Email" />
    </main>
  );
}
