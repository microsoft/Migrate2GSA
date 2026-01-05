import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Automated Migration Toolkit',
    Svg: require('@site/static/img/undraw_programming_j1zw.svg').default,
    description: (
      <>
        Simplify your transition from other SSE solutions to Microsoft Global Secure Access with automated export, transformation, and provisioning tools.
      </>
    ),
  },
  {
    title: 'Reduce Migration Risk',
    Svg: require('@site/static/img/undraw_spreadsheet_uj8z.svg').default,
    description: (
      <>
        Validate and transform policies accurately with built-in mapping logic that handles architectural differences between platforms.
      </>
    ),
  },
  {
    title: 'Open Source & Extensible',
    Svg: require('@site/static/img/undraw_online-community_3o0l.svg').default,
    description: (
      <>
        Community-driven PowerShell module with transparent code and the ability to customize for your unique requirements.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
        <div className="row">
          <div className="col text--center padding-top--lg">
            <p style={{ fontSize: '1.1rem', color: 'var(--ifm-color-emphasis-700)' }}>
              ❤️ Made possible by customers who share configuration samples. We don't have access to third-party products, so your contributions make these tools possible.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
