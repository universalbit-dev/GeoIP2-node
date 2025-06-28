module.exports = {
  apps: [{
    name: 'geoip-cluster',
    script: './geoip.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
